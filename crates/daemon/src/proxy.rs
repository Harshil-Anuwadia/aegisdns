use std::{collections::HashMap, sync::{Arc, Mutex, OnceLock, atomic::{AtomicUsize, Ordering}}, time::{Duration, Instant}, net::{IpAddr, SocketAddr}};
use tokio::{net::{UdpSocket, TcpListener, TcpStream}, sync::{RwLock, Semaphore}, io::{AsyncReadExt, AsyncWriteExt}};
use hickory_proto::{op::{Message, ResponseCode}, rr::{RData, RecordType}};
use analytics::AnalyticsDb;
use policy::{PolicyEngine, PolicyDecision, AllowReason};
use blocklist::BlocklistManager;
use moka::future::Cache;
use crate::anomaly::AnomalyDetector;
use config::dns;

#[cfg(test)] #[path = "proxy_tests.rs"] mod proxy_tests;

#[derive(Clone)]
pub struct DnsProxy {
    listen_addr: String,
    upstream_addr: String,
    host_ip: String,
    analytics: Arc<AnalyticsDb>,
    action_domains: crate::actions::ActionDomains,
    policy: Arc<RwLock<PolicyEngine>>,
    blocklist: Arc<RwLock<BlocklistManager>>,
    fast_flux: Arc<RwLock<risk::FastFluxDetector>>,
    anomaly: Arc<AnomalyDetector>,
    telegram_config: Arc<RwLock<crate::telegram::TelegramConfig>>,
    device_registry: Arc<RwLock<crate::device_registry::DeviceRegistry>>,
    admission: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    client_limits: moka::sync::Cache<IpAddr, Arc<Semaphore>>,
    typo_cache: Cache<String, bool>,
    privacy: Arc<crate::privacy::PrivacyGuard>,
    ip_metadata: crate::relationships::IpMetadata,
}

impl DnsProxy {
    // Keep construction compatibility for the dashboard while Unbound owns the DNS cache.
    #[allow(clippy::too_many_arguments)]
    pub fn new(listen: &str, upstream: &str, host_ip: &str, analytics: Arc<AnalyticsDb>,
        action_domains: crate::actions::ActionDomains, policy: Arc<RwLock<PolicyEngine>>, blocklist: Arc<RwLock<BlocklistManager>>,
        fast_flux: Arc<RwLock<risk::FastFluxDetector>>, anomaly: Arc<AnomalyDetector>,
        _response_cache: Cache<(String,u16),(Vec<u8>,Instant)>, telegram_config: Arc<RwLock<crate::telegram::TelegramConfig>>,
        device_registry: Arc<RwLock<crate::device_registry::DeviceRegistry>>, _upstream_config: crate::upstream::SharedUpstreamDns,
        privacy: Arc<crate::privacy::PrivacyGuard>, ip_metadata: crate::relationships::IpMetadata) -> Self {
        Self { listen_addr:listen.into(), upstream_addr:upstream.into(), host_ip:host_ip.into(), analytics, action_domains, policy, blocklist, fast_flux,
            anomaly, telegram_config, device_registry, admission:Arc::new(Semaphore::new(256)), connections:Arc::new(Semaphore::new(128)),
            client_limits:moka::sync::Cache::builder().max_capacity(10_000).time_to_idle(Duration::from_secs(300)).build(),
            typo_cache:Cache::builder().max_capacity(100_000).time_to_idle(Duration::from_secs(3600)).build(), privacy, ip_metadata }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        // Bind both before entering either loop; failures propagate to the supervisor.
        let addr:SocketAddr=self.listen_addr.parse()?;
        let udp = Arc::new(UdpSocket::from_std(bind_socket(addr,false)?.into())?);
        let tcp = TcpListener::from_std(bind_socket(addr,true)?.into())?;
        tracing::info!("DNS listening on {}", self.listen_addr);
        tokio::try_join!(self.run_udp(udp), self.run_tcp(tcp))?;
        Ok(())
    }

    fn client_ip(&self, ip: IpAddr) -> String {
        if ip.is_loopback() && !self.host_ip.is_empty() { self.host_ip.clone() }
        else { ip.to_string() }
    }

    async fn run_udp(&self, socket: Arc<UdpSocket>) -> anyhow::Result<()> {
        let mut buf = vec![0; 65535];
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                biased;
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                received = socket.recv_from(&mut buf) => {
                    let (len, src) = received?;
                    if !config::allowed_dns_client(src.ip()) { continue; }
                    let bytes = buf[..len].to_vec();
                    let Ok(global) = self.admission.clone().try_acquire_owned() else {
                        if let Some(response)=overload_response(&bytes,false) { let _=socket.send_to(&response,src).await; }
                        continue;
                    };
                    let limit = self.client_limits.get_with(src.ip(), || Arc::new(Semaphore::new(32)));
                    let Ok(client) = limit.try_acquire_owned() else {
                        if let Some(response)=overload_response(&bytes,false) { let _=socket.send_to(&response,src).await; }
                        continue;
                    };
                    let proxy = self.clone(); let sock = socket.clone();
                    tasks.spawn(async move {
                        let (_global, _client) = (global,client);
                        if let Some(resp) = proxy.process(&bytes, &proxy.client_ip(src.ip()), false).await { let _ = sock.send_to(&resp, src).await; }
                    });
                }
            }
        }
    }

    async fn run_tcp(&self, listener: TcpListener) -> anyhow::Result<()> {
        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                biased;
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = listener.accept() => {
                    let (mut stream, src) = accepted?;
                    if !config::allowed_dns_client(src.ip()) { continue; }
                    let Ok(connection) = self.connections.clone().try_acquire_owned() else { continue; };
                    let limit = self.client_limits.get_with(src.ip(), || Arc::new(Semaphore::new(32)));
                    let Ok(client) = limit.try_acquire_owned() else { continue; };
                    let proxy = self.clone();
                    tasks.spawn(async move {
                        let (_connection, _client) = (connection, client);
                        // Finite lifetime and idle deadlines prevent idle/partial-frame exhaustion.
                        let _ = tokio::time::timeout(Duration::from_secs(120), async {
                            loop {
                                let request = tokio::time::timeout(Duration::from_secs(10), read_frame(&mut stream)).await;
                                let Ok(Ok(bytes)) = request else { break; };
                                let Ok(_permit) = proxy.admission.clone().try_acquire_owned() else {
                                    if let Some(response)=overload_response(&bytes,true) { let _=write_frame(&mut stream,&response).await; }
                                    continue;
                                };
                                let Some(resp) = proxy.process(&bytes, &proxy.client_ip(src.ip()), true).await else { break; };
                                if !matches!(tokio::time::timeout(Duration::from_secs(5), write_frame(&mut stream, &resp)).await, Ok(Ok(()))) { break; }
                            }
                        }).await;
                    });
                }
            }
        }
    }

    async fn decision(&self, domain: &str, client: &str) -> PolicyDecision {
        let profile = self.device_registry.read().await.get_profile(client).to_string();
        let p = self.policy.read().await;
        if p.emergency_mode { return PolicyDecision::Allowed(AllowReason::Emergency); }
        if profile == "bypass" { return PolicyDecision::Allowed(AllowReason::Bypass); }
        let decision = p.evaluate_without_typosquatting(domain, Some(client));
        drop(p);
        match &decision {
            PolicyDecision::Blocked(_) => return decision,
            PolicyDecision::Allowed(r) if r.bypass_filtering() => return decision,
            _ => {}
        }
        let canonical = config::canonical_domain(domain);
        if self.typo_cache.get_with(canonical.clone(), async move { PolicyEngine::is_typosquatting(&canonical) }).await {
            return PolicyDecision::Blocked(policy::BlockReason::Phishing);
        }
        if self.privacy.should_block(client,domain).await { return PolicyDecision::Blocked(policy::BlockReason::PrivacyBudget); }
        if self.blocklist.read().await.is_blocked(domain) { return PolicyDecision::Blocked(policy::BlockReason::Tracker); }
        // Heuristics are enforced only in the explicitly selected strict profile.
        if profile == "strict" && risk::score_domain(domain).score >= 70 {
            return PolicyDecision::Blocked(policy::BlockReason::Security);
        }
        decision
    }

    async fn relationships(&self,domain:&str,client:&str,response:&Message)->Vec<analytics::RelationshipObservation>{
        use crate::relationships::{application,contains_identifier,linked_observation,observation,tracking_company};
        let mut edges=vec![observation("requested_by",client,"device")];
        if let Some(app)=application(domain){edges.push(observation("used_by",&app,"application"));}
        if let Some(company)=tracking_company(domain){edges.push(observation("contacts",&company,"company"));}
        if contains_identifier(domain){edges.push(observation("contains_identifier",domain,"domain"));}
        if self.blocklist.read().await.is_blocked(domain){edges.push(observation("listed_by","Active blocklists","blocklist"));}
        for record in response.answers.iter().chain(&response.authorities).chain(&response.additionals){
            let mut owner=config::canonical_domain(&record.name.to_ascii());
            if owner.is_empty(){owner=domain.to_string();}
            match &record.data{
            RData::CNAME(name)=>edges.push(linked_observation(&owner,"domain","canonical_name",&config::canonical_domain(&name.0.to_ascii()),"domain")),
            RData::A(ip)=>edges.extend(self.ip_metadata.observations(&owner,ip.0.into())),
            RData::AAAA(ip)=>edges.extend(self.ip_metadata.observations(&owner,ip.0.into())),
            RData::NS(name)=>edges.push(linked_observation(&owner,"domain","nameserver",&config::canonical_domain(&name.0.to_ascii()),"nameserver")),
            RData::PTR(name)=>edges.push(linked_observation(&owner,"domain","points_to",&config::canonical_domain(&name.0.to_ascii()),"domain")),
            RData::TLSA(tlsa)=>{
                use sha2::{Digest,Sha256};
                let fingerprint=format!("sha256:{:x}",Sha256::digest(&tlsa.cert_data));
                edges.push(linked_observation(&owner,"domain","certificate_association",&fingerprint,"certificate"));
            }
            RData::SVCB(svcb)=>{let target=config::canonical_domain(&svcb.target_name.to_ascii());if !target.is_empty(){edges.push(linked_observation(&owner,"domain","service_target",&target,"domain"));}}
            RData::HTTPS(https)=>{let target=config::canonical_domain(&https.0.target_name.to_ascii());if !target.is_empty(){edges.push(linked_observation(&owner,"domain","service_target",&target,"domain"));}}
            _=>{}
        }}
        let mut seen=std::collections::HashSet::new();
        edges.retain(|edge|seen.insert((edge.source.clone(),edge.source_kind.clone(),edge.relation.clone(),edge.target.clone(),edge.target_kind.clone())));
        edges
    }

    async fn process(&self, bytes: &[u8], client: &str, tcp: bool) -> Option<Vec<u8>> {
        let q = dns::parse_query(bytes)?;
        let domain = config::canonical_domain(&q.queries[0].name.to_ascii());
        let qt = q.queries[0].query_type;
        if q.edns.as_ref().is_some_and(|e| e.version() != 0) { return dns::encode_for_client(&dns::reply(&q, ResponseCode::BADVERS), &q, tcp); }
        let start = Instant::now();
        let mut blocked = self.anomaly.check_and_record(client).await;
        let decision = self.decision(&domain, client).await;
        blocked |= matches!(decision, PolicyDecision::Blocked(_));
        let bypass = matches!(decision, PolicyDecision::Allowed(ref reason) if reason.bypass_filtering());
        let response = if blocked {
            dns::negative(&q, ResponseCode::NXDomain)
        } else if dns::local_zone(&domain) && self.action_domains.contains(&domain) {
            // An action record does not bypass policy or execute anything during DNS lookup.
            match (qt, self.host_ip.parse()) {
                (RecordType::A, Ok(ip)) => dns::ipv4_reply(&q, ip),
                _ => dns::negative(&q, ResponseCode::NoError),
            }
        } else if !bypass && self.policy.read().await.safe_search_enabled && safe_target(&domain).is_some()
            && matches!(qt, RecordType::A | RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB) {
            dns::cname_reply(&q, safe_target(&domain).unwrap()).unwrap_or_else(||dns::reply(&q,ResponseCode::ServFail))
        } else {
            let local = dns::local_zone(&domain);
            // Unbound owns response caching and TTL aging. Every answer must still
            // pass this client's current alias policy and relationship accounting.
            // Local-zone names go to the authoritative OpenRoot server; the
            // address is shared with that binary so the two cannot drift.
            let openroot_addr;
            let addr = if local {
                openroot_addr = config::paths::get_openroot_addr();
                openroot_addr.as_str()
            } else {
                &self.upstream_addr
            };
            // All external data, including configured forwarders, goes through validating Unbound.
            match tokio::time::timeout(Duration::from_secs(10), exchange(addr, &q, tcp)).await {
                Ok(Ok(r)) => {
                    let mut unsafe_answer = false;
                    let mut resolved_ips = Vec::new();
                    for record in r.answers.iter().chain(&r.additionals) {
                        match &record.data {
                            RData::CNAME(name) if !bypass => {
                                if matches!(self.decision(&config::canonical_domain(&name.0.to_ascii()), client).await, PolicyDecision::Blocked(_)) { unsafe_answer = true; }
                            }
                            RData::A(ip) if !local => { let ip=IpAddr::from(ip.0); unsafe_answer |= config::is_internal_address(ip); resolved_ips.push(ip); },
                            RData::AAAA(ip) if !local => { let ip=IpAddr::from(ip.0); unsafe_answer |= config::is_internal_address(ip); resolved_ips.push(ip); },
                            _ => {}
                        }
                    }
                    if !local && !bypass && !resolved_ips.is_empty() {
                        let mut detector=self.fast_flux.write().await;
                        for ip in resolved_ips { detector.record_resolution(&domain,ip); }
                        unsafe_answer |= detector.is_fast_flux(&domain);
                    }
                    if unsafe_answer { blocked = true; dns::negative(&q, ResponseCode::NXDomain) } else {
                        r
                    }
                }
                _ => dns::reply(&q, ResponseCode::ServFail),
            }
        };
        let failed = response.metadata.response_code == ResponseCode::ServFail;
        if failed { let _ = self.analytics.record_failure(&domain, client).await; }
        else {
            let relationships=self.relationships(&domain,client,&response).await;
            self.privacy.record(client,&domain,&relationships);
            let _ = self.analytics.record_query_with_relationships(&domain, blocked, start.elapsed().as_millis() as u32, client,relationships).await;
        }
        let tg = self.telegram_config.read().await.clone();
        if tg.enabled {
            let score = risk::score_domain(&domain).score;
            if score >= tg.threat_threshold || (blocked && tg.notify_blocked) {
                crate::telegram::send_alert(
                    self.telegram_config.clone(),
                    format!(
                        "DNS {}: {} from {} (risk score {})",
                        if blocked { "request blocked" } else { "threat detected" },
                        config::html_escape(&domain),
                        config::html_escape(client),
                        score
                    ),
                );
            }
        }
        dns::encode_for_client(&response, &q, tcp)
    }
}

fn safe_target(domain: &str) -> Option<&'static str> {
    let base = domain.strip_prefix("www.").unwrap_or(domain);
    match base {
        "google.com" | "google.co.in" | "google.co.uk" | "google.com.au" | "google.ca" | "google.de" | "google.fr" | "google.co.jp" => Some("forcesafesearch.google.com."),
        "youtube.com" | "m.youtube.com" | "youtubei.googleapis.com" | "youtube.googleapis.com" | "youtube-nocookie.com" => Some("restrict.youtube.com."),
        "bing.com" => Some("strict.bing.com."),
        "duckduckgo.com" => Some("safe.duckduckgo.com."),
        _ => None,
    }
}

async fn read_frame(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let len = stream.read_u16().await? as usize;
    if len < 12 { return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "short DNS frame")); }
    let mut bytes = vec![0; len]; stream.read_exact(&mut bytes).await?; Ok(bytes)
}
async fn write_frame(stream: &mut TcpStream, bytes: &[u8]) -> std::io::Result<()> {
    let len = u16::try_from(bytes.len()).map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData,"DNS frame too large"))?;
    stream.write_u16(len).await?; stream.write_all(bytes).await
}

fn overload_response(bytes: &[u8], tcp: bool) -> Option<Vec<u8>> {
    let query=dns::parse_query(bytes)?;
    dns::encode_for_client(&dns::reply(&query,ResponseCode::ServFail),&query,tcp)
}

struct AddressPool {
    next: AtomicUsize,
    sockets: Vec<tokio::sync::Mutex<Option<UdpSocket>>>,
}

impl AddressPool {
    fn new() -> Self {
        Self {
            next: AtomicUsize::new(0),
            sockets: (0..32).map(|_|tokio::sync::Mutex::new(None)).collect(),
        }
    }
}

struct UpstreamSocketPool {
    addresses: Mutex<HashMap<SocketAddr,Arc<AddressPool>>>,
}

impl UpstreamSocketPool {
    fn address(&self,addr:SocketAddr)->Arc<AddressPool> {
        let mut addresses=self.addresses.lock().unwrap_or_else(|poisoned|poisoned.into_inner());
        addresses.entry(addr).or_insert_with(||Arc::new(AddressPool::new())).clone()
    }
}

static UPSTREAM_SOCKETS: OnceLock<UpstreamSocketPool> = OnceLock::new();

async fn exchange(addr: &str, original: &Message, retry_tcp: bool) -> anyhow::Result<Message> {
    let addr: SocketAddr = addr.parse()?;
    let mut q = original.clone();
    // A new random upstream ID; never trust a caller-controlled ID for response matching.
    q.metadata.id = Message::query().metadata.id;
    let data = q.to_vec()?;
    let pool=UPSTREAM_SOCKETS.get_or_init(||UpstreamSocketPool{addresses:Mutex::new(HashMap::new())}).address(addr);
    let slot=pool.next.fetch_add(1,Ordering::Relaxed)%pool.sockets.len();
    let mut socket=pool.sockets[slot].lock().await;
    if socket.is_none() {
        let sock=UdpSocket::bind(if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await?;
        sock.connect(addr).await?;
        *socket=Some(sock);
    }
    let sock=socket.as_ref().expect("upstream socket initialized");
    if let Err(error)=sock.send(&data).await { *socket=None; return Err(error.into()); }
    let mut buf = vec![0; 65535];
    loop {
        let n = match sock.recv(&mut buf).await { Ok(n)=>n, Err(error)=>{*socket=None;return Err(error.into());} };
        let Ok(mut response) = Message::from_vec(&buf[..n]) else { continue; };
        if !dns::valid_response(&q, &response) { continue; }
        if response.metadata.truncation && retry_tcp {
            let mut stream = TcpStream::connect(addr).await?;
            write_frame(&mut stream, &data).await?;
            response = Message::from_vec(&read_frame(&mut stream).await?)?;
            anyhow::ensure!(dns::valid_response(&q, &response) && !response.metadata.truncation, "invalid TCP upstream response");
        }
        response.metadata.id = original.metadata.id;
        return Ok(response);
    }
}

fn bind_socket(addr:SocketAddr,tcp:bool)->std::io::Result<socket2::Socket> {
    let socket=socket2::Socket::new(if addr.is_ipv6(){socket2::Domain::IPV6}else{socket2::Domain::IPV4},if tcp{socket2::Type::STREAM}else{socket2::Type::DGRAM},None)?;
    if addr.is_ipv6(){socket.set_only_v6(true)?;}
    if tcp {socket.set_reuse_address(true)?;}
    socket.set_nonblocking(true)?; socket.bind(&addr.into())?;
    if tcp {socket.listen(128)?;}
    Ok(socket)
}
