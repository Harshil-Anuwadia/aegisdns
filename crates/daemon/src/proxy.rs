use std::{sync::Arc, time::{Duration, Instant}, net::{IpAddr, SocketAddr}};
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
    policy: Arc<RwLock<PolicyEngine>>,
    blocklist: Arc<RwLock<BlocklistManager>>,
    anomaly: Arc<AnomalyDetector>,
    telegram_config: Arc<RwLock<crate::telegram::TelegramConfig>>,
    device_registry: Arc<RwLock<crate::device_registry::DeviceRegistry>>,
    admission: Arc<Semaphore>,
    connections: Arc<Semaphore>,
    client_limits: moka::sync::Cache<IpAddr, Arc<Semaphore>>,
}

impl DnsProxy {
    // Keep construction compatibility for the dashboard while Unbound owns the DNS cache.
    #[allow(clippy::too_many_arguments)]
    pub fn new(listen: &str, upstream: &str, host_ip: &str, analytics: Arc<AnalyticsDb>,
        policy: Arc<RwLock<PolicyEngine>>, blocklist: Arc<RwLock<BlocklistManager>>,
        _fast_flux: Arc<RwLock<risk::FastFluxDetector>>, anomaly: Arc<AnomalyDetector>,
        _cache: Cache<(String,u16),(Vec<u8>,Instant)>, telegram_config: Arc<RwLock<crate::telegram::TelegramConfig>>,
        device_registry: Arc<RwLock<crate::device_registry::DeviceRegistry>>, _upstream_config: crate::upstream::SharedUpstreamDns) -> Self {
        Self { listen_addr:listen.into(), upstream_addr:upstream.into(), host_ip:host_ip.into(), analytics, policy, blocklist,
            anomaly, telegram_config, device_registry, admission:Arc::new(Semaphore::new(256)), connections:Arc::new(Semaphore::new(128)),
            client_limits:moka::sync::Cache::builder().max_capacity(10_000).time_to_idle(Duration::from_secs(300)).build() }
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
                    let Ok(global) = self.admission.clone().try_acquire_owned() else { continue; };
                    let limit = self.client_limits.get_with(src.ip(), || Arc::new(Semaphore::new(32)));
                    let Ok(client) = limit.try_acquire_owned() else { continue; };
                    let bytes = buf[..len].to_vec(); let proxy = self.clone(); let sock = socket.clone();
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
                                let Ok(_permit) = proxy.admission.clone().try_acquire_owned() else { break; };
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
        let decision = p.evaluate(domain, Some(client)); drop(p);
        match &decision {
            PolicyDecision::Blocked(_) => return decision,
            PolicyDecision::Allowed(r) if r.bypass_filtering() => return decision,
            _ => {}
        }
        if self.blocklist.read().await.is_blocked(domain) { return PolicyDecision::Blocked(policy::BlockReason::Tracker); }
        // Heuristics are enforced only in the explicitly selected strict profile.
        if profile == "strict" && risk::score_domain(domain).score >= 70 {
            return PolicyDecision::Blocked(policy::BlockReason::Security);
        }
        decision
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
        } else if crate::actions::get_action_for_domain_db(&domain, &self.analytics).await.is_some() {
            // An action record does not bypass policy or execute anything during DNS lookup.
            match (qt, self.host_ip.parse()) {
                (RecordType::A, Ok(ip)) => dns::ipv4_reply(&q, ip),
                _ => dns::negative(&q, ResponseCode::NoError),
            }
        } else if !bypass && self.policy.read().await.safe_search_enabled && safe_ip(&domain).is_some()
            && matches!(qt, RecordType::A | RecordType::AAAA | RecordType::HTTPS | RecordType::SVCB) {
            if qt == RecordType::A { dns::ipv4_reply(&q, safe_ip(&domain).unwrap()) }
            else { dns::negative(&q, ResponseCode::NoError) }
        } else {
            let local = dns::local_zone(&domain);
            let addr = if local { "127.0.0.1:5354" } else { &self.upstream_addr };
            // All external data, including configured forwarders, goes through validating Unbound.
            match tokio::time::timeout(Duration::from_secs(10), exchange(addr, &q)).await {
                Ok(Ok(r)) => {
                    let mut unsafe_answer = false;
                    for record in r.answers.iter().chain(&r.additionals) {
                        match &record.data {
                            RData::CNAME(name) if !bypass => {
                                if matches!(self.decision(&config::canonical_domain(&name.0.to_ascii()), client).await, PolicyDecision::Blocked(_)) { unsafe_answer = true; }
                            }
                            RData::A(ip) if !local => unsafe_answer |= config::is_internal_address(ip.0.into()),
                            RData::AAAA(ip) if !local => unsafe_answer |= config::is_internal_address(ip.0.into()),
                            _ => {}
                        }
                    }
                    if unsafe_answer { blocked = true; dns::negative(&q, ResponseCode::NXDomain) } else { r }
                }
                _ => dns::reply(&q, ResponseCode::ServFail),
            }
        };
        let failed = response.metadata.response_code == ResponseCode::ServFail;
        if failed { let _ = self.analytics.record_failure(&domain, client).await; }
        else { let _ = self.analytics.record_query(&domain, blocked, start.elapsed().as_millis() as u32, client).await; }
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

fn safe_ip(domain: &str) -> Option<std::net::Ipv4Addr> {
    let base = domain.strip_prefix("www.").unwrap_or(domain);
    let ip = match base {
        "google.com" | "google.co.in" | "google.co.uk" | "google.com.au" | "google.ca" | "google.de" | "google.fr" | "google.co.jp" => [216,239,38,120],
        "youtube.com" | "m.youtube.com" | "youtubei.googleapis.com" | "youtube.googleapis.com" | "youtube-nocookie.com" => [216,239,38,119],
        "bing.com" => [204,79,197,220], "duckduckgo.com" => [52,149,24,70], _ => return None,
    };
    Some(ip.into())
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

async fn exchange(addr: &str, original: &Message) -> anyhow::Result<Message> {
    let addr: SocketAddr = addr.parse()?;
    let mut q = original.clone();
    // A new random upstream ID; never trust a caller-controlled ID for response matching.
    q.metadata.id = Message::query().metadata.id;
    let data = q.to_vec()?;
    let sock = UdpSocket::bind(if addr.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).await?;
    sock.connect(addr).await?;
    sock.send(&data).await?;
    let mut buf = vec![0; 65535];
    loop {
        let n = sock.recv(&mut buf).await?;
        let Ok(mut response) = Message::from_vec(&buf[..n]) else { continue; };
        if !dns::valid_response(&q, &response) { continue; }
        if response.metadata.truncation {
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
