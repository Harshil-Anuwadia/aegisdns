use std::sync::Arc;

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod proxy_tests;
use tokio::net::UdpSocket;
use dns_parser::Packet;
use analytics::AnalyticsDb;
use policy::{PolicyEngine, PolicyDecision};
use blocklist::BlocklistManager;
use fallback::FallbackEngine;
use tokio::sync::RwLock;
use std::time::{Instant, Duration};
use moka::future::Cache;
use crate::anomaly::AnomalyDetector;

pub struct DnsProxy {
    listen_addr: String,
    upstream_addr: String,
    analytics: Arc<AnalyticsDb>,
    policy: Arc<RwLock<PolicyEngine>>,
    blocklist: Arc<RwLock<BlocklistManager>>,
    fallback: Arc<RwLock<FallbackEngine>>,
    fast_flux: Arc<RwLock<risk::FastFluxDetector>>,
    http_client: reqwest::Client,
    anomaly: Arc<AnomalyDetector>,
    cache: Cache<(String, u16), (Vec<u8>, Instant)>,
    semaphore: Arc<tokio::sync::Semaphore>,
}

impl DnsProxy {
    pub fn new(
        listen: &str, 
        upstream: &str, 
        analytics: Arc<AnalyticsDb>, 
        policy: Arc<RwLock<PolicyEngine>>, 
        blocklist: Arc<RwLock<BlocklistManager>>, 
        fallback: Arc<RwLock<FallbackEngine>>,
        fast_flux: Arc<RwLock<risk::FastFluxDetector>>,
        anomaly: Arc<AnomalyDetector>,
        cache: Cache<(String, u16), (Vec<u8>, Instant)>,
    ) -> Self {
        Self {
            listen_addr: listen.to_string(),
            upstream_addr: upstream.to_string(),
            analytics,
            policy,
            blocklist,
            fallback,
            fast_flux,
            // Always set timeouts to prevent hung tasks from leaking resources
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .connect_timeout(std::time::Duration::from_secs(3))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
            anomaly,
            cache,
            semaphore: Arc::new(tokio::sync::Semaphore::new(1000)),
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let listen_addr = self.listen_addr.clone();
        
        let udp_proxy = Self {
            listen_addr: self.listen_addr.clone(),
            upstream_addr: self.upstream_addr.clone(),
            analytics: self.analytics.clone(),
            policy: self.policy.clone(),
            blocklist: self.blocklist.clone(),
            fallback: self.fallback.clone(),
            fast_flux: self.fast_flux.clone(),
            http_client: self.http_client.clone(),
            anomaly: self.anomaly.clone(),
            cache: self.cache.clone(),
            semaphore: self.semaphore.clone(),
        };

        let tcp_proxy = Self {
            listen_addr: self.listen_addr.clone(),
            upstream_addr: self.upstream_addr.clone(),
            analytics: self.analytics.clone(),
            policy: self.policy.clone(),
            blocklist: self.blocklist.clone(),
            fallback: self.fallback.clone(),
            fast_flux: self.fast_flux.clone(),
            http_client: self.http_client.clone(),
            anomaly: self.anomaly.clone(),
            cache: self.cache.clone(),
            semaphore: self.semaphore.clone(),
        };

        tracing::info!("DNS Proxy listening on {} and forwarding to {}", listen_addr, self.upstream_addr);

        let udp_handle = tokio::spawn(async move {
            udp_proxy.run_udp().await;
        });

        let tcp_handle = tokio::spawn(async move {
            tcp_proxy.run_tcp().await;
        });

        let _ = tokio::try_join!(udp_handle, tcp_handle);

        Ok(())
    }

    async fn run_udp(self) {
        let socket = match UdpSocket::bind(&self.listen_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::error!("Failed to bind UDP socket: {}", e);
                return;
            }
        };

        loop {
            let mut buf = [0u8; 4096];
            let (len, src_addr) = match socket.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(e) => {
                    tracing::error!("Failed to receive UDP: {}", e);
                    continue;
                }
            };

            let packet_data = buf[..len].to_vec();
            let socket = socket.clone();
            
            let client_ip = src_addr.ip().to_string();
            let upstream_addr = self.upstream_addr.clone();
            let analytics = self.analytics.clone();
            let policy = self.policy.clone();
            let blocklist = self.blocklist.clone();
            let fallback = self.fallback.clone();
            let fast_flux = self.fast_flux.clone();
            let http_client = self.http_client.clone();
            let anomaly = self.anomaly.clone();
            let cache = self.cache.clone();
            let semaphore = self.semaphore.clone();

            tokio::spawn(async move {
                if let Some(resp) = process_query(
                    packet_data, client_ip, upstream_addr, analytics, policy, blocklist, 
                    fallback, fast_flux, http_client, anomaly, cache, semaphore
                ).await {
                    let _ = socket.send_to(&resp, src_addr).await;
                }
            });
        }
    }

    async fn run_tcp(self) {
        let listener = match tokio::net::TcpListener::bind(&self.listen_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind TCP socket: {}", e);
                return;
            }
        };

        loop {
            let (mut stream, src_addr) = match listener.accept().await {
                Ok(res) => res,
                Err(e) => {
                    tracing::error!("Failed to accept TCP: {}", e);
                    continue;
                }
            };

            let client_ip = src_addr.ip().to_string();
            let upstream_addr = self.upstream_addr.clone();
            let analytics = self.analytics.clone();
            let policy = self.policy.clone();
            let blocklist = self.blocklist.clone();
            let fallback = self.fallback.clone();
            let fast_flux = self.fast_flux.clone();
            let http_client = self.http_client.clone();
            let anomaly = self.anomaly.clone();
            let cache = self.cache.clone();
            let semaphore = self.semaphore.clone();

            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                
                let mut len_buf = [0u8; 2];
                if stream.read_exact(&mut len_buf).await.is_err() {
                    return;
                }
                let len = u16::from_be_bytes(len_buf) as usize;
                let mut packet_data = vec![0u8; len];
                if stream.read_exact(&mut packet_data).await.is_err() {
                    return;
                }

                if let Some(resp) = process_query(
                    packet_data, client_ip, upstream_addr, analytics, policy, blocklist, 
                    fallback, fast_flux, http_client, anomaly, cache, semaphore
                ).await {
                    let resp_len = (resp.len() as u16).to_be_bytes();
                    let mut out = Vec::with_capacity(2 + resp.len());
                    out.extend_from_slice(&resp_len);
                    out.extend_from_slice(&resp);
                    let _ = stream.write_all(&out).await;
                }
            });
        }
    }
}

async fn process_query(
    packet_data: Vec<u8>,
    client_ip: String,
    upstream_addr: String,
    analytics: Arc<AnalyticsDb>,
    policy: Arc<RwLock<PolicyEngine>>,
    blocklist: Arc<RwLock<BlocklistManager>>,
    fallback: Arc<RwLock<FallbackEngine>>,
    fast_flux: Arc<RwLock<risk::FastFluxDetector>>,
    http_client: reqwest::Client,
    anomaly: Arc<AnomalyDetector>,
    cache: Cache<(String, u16), (Vec<u8>, Instant)>,
    semaphore: Arc<tokio::sync::Semaphore>,
) -> Option<Vec<u8>> {
    // Parse DNS packet to extract domain and query type
    let (domain, qtype) = match Packet::parse(&packet_data) {
        Ok(packet) => {
            if let Some(q) = packet.questions.first() {
                (q.qname.to_string(), q.qtype)
            } else {
                ("".to_string(), dns_parser::QueryType::A)
            }
        }
        Err(_) => ("".to_string(), dns_parser::QueryType::A),
    };

    if domain.is_empty() { return None; }
    let base_domain = if domain.starts_with("www.") { &domain[4..] } else { &domain[..] };

    // Calculate safe end of question section to strip EDNS0 OPT records
    let mut offset = 12;
    let mut p = &packet_data[12..];
    while !p.is_empty() {
        let len = p[0] as usize;
        offset += 1;
        p = &p[1..];
        if len == 0 { break; }
        if (len & 0xC0) == 0xC0 {
            offset += 1;
            break;
        }
        if p.len() < len { break; }
        offset += len;
        p = &p[len..];
    }
    offset += 4;
    if offset > packet_data.len() { offset = packet_data.len(); }

    // Helper: build a minimal SERVFAIL response
    let make_servfail = |pkt: &[u8], end: usize| -> Vec<u8> {
        let mut resp = pkt[0..end].to_vec();
        resp[2] |= 0x80;
        resp[3] &= 0xF0;
        resp[3] |= 0x02; // RCODE SERVFAIL
        resp[6] = 0; resp[7] = 0;
        resp[8] = 0; resp[9] = 0;
        resp[10] = 0; resp[11] = 0;
        resp
    };

    // Helper: build a blocked (NXDOMAIN/zero-IP) response with dynamic IPs
    let make_blocked_resp = |pkt: &[u8], end: usize, qt: dns_parser::QueryType| -> Vec<u8> {
        static CACHE: std::sync::OnceLock<std::sync::Mutex<(u64, Vec<[u8; 4]>)>> = std::sync::OnceLock::new();
        let cache = CACHE.get_or_init(|| std::sync::Mutex::new((0, vec![[127, 0, 0, 1]])));
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
        let mut lock = cache.lock().unwrap();
        if now - lock.0 > 5 { // cache for 5 seconds
            let mut new_ips = Vec::new();
            if let Ok(content) = std::fs::read_to_string("/app/config.json").or_else(|_| std::fs::read_to_string("config.json")) {
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&content) {
                    if let Some(arr) = v.get("host_ips").and_then(|a| a.as_array()) {
                        for ip_val in arr {
                            if let Some(ip_str) = ip_val.as_str() {
                                let parts: Vec<u8> = ip_str.split('.').filter_map(|s| s.parse().ok()).collect();
                                if parts.len() == 4 { new_ips.push([parts[0], parts[1], parts[2], parts[3]]); }
                            }
                        }
                    }
                }
            }
            if new_ips.is_empty() {
                let env_ip = std::env::var("AEGIS_HOST_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
                let parts: Vec<u8> = env_ip.split('.').filter_map(|s| s.parse().ok()).collect();
                if parts.len() == 4 { new_ips.push([parts[0], parts[1], parts[2], parts[3]]); } else { new_ips.push([127, 0, 0, 1]); }
            }
            *lock = (now, new_ips);
        }
        let target_ips = lock.1.clone();
        drop(lock);

        let mut resp = pkt[0..end].to_vec();
        resp[2] |= 0x80; // QR=1
        resp[3] |= 0x80; // RA=1
        resp[3] &= 0xF0; // NOERROR
        resp[8] = 0; resp[9] = 0;
        resp[10] = 0; resp[11] = 0;
        match qt {
            dns_parser::QueryType::A => {
                resp[6] = 0; 
                resp[7] = target_ips.len() as u8;
                for ip in target_ips {
                    let mut a_rec = vec![0xC0,0x0C,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x04];
                    a_rec.extend_from_slice(&ip);
                    resp.extend_from_slice(&a_rec);
                }
            }
            dns_parser::QueryType::AAAA => {
                resp[6] = 0; resp[7] = 1;
                resp.extend_from_slice(&[0xC0,0x0C,0x00,0x1C,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
            }
            _ => { resp[6] = 0; resp[7] = 0; } // NODATA
        }
        resp
    };

    // Anomaly Detection: BEFORE policy check
    if anomaly.check_and_record(&client_ip).await {
        let mut resp = packet_data[0..offset].to_vec();
        resp[2] |= 0x80; // QR=1
        resp[3] &= 0xF0;
        resp[3] |= 0x03; // NXDOMAIN
        resp[6] = 0; resp[7] = 0;
        resp[8] = 0; resp[9] = 0;
        resp[10] = 0; resp[11] = 0;
        
        if client_ip != "127.0.0.2" { let _ = analytics.record_query(&domain, true, 0, &client_ip).await; } return Some(resp);
    }



    // Custom DNS Actions Engine Intercept
    if crate::actions::get_action_for_domain_db(&domain, &analytics).is_some() {
        let resp = make_blocked_resp(&packet_data, offset, qtype);
        if client_ip != "127.0.0.2" { let _ = analytics.record_query(&domain, false, 0, &client_ip).await; }
        return Some(resp);
    }

    // Policy + Blocklist decision
    let decision = policy.read().await.evaluate(&domain, Some(&client_ip));
    let safe_search_on = policy.read().await.safe_search_enabled;
    let mut is_explicitly_allowed = false;
    let blocked = match decision {
        PolicyDecision::Allowed(ref reason) if reason == "Explicit user allow" || reason == "Temporary allow" || reason == "Explicit device allow" => {
            is_explicitly_allowed = true;
            false
        },
        PolicyDecision::Allowed(_) => blocklist.read().await.is_blocked(&domain),
        PolicyDecision::Blocked(_) => true,
    };

    if blocked {
        let resp = make_blocked_resp(&packet_data, offset, qtype);
        if client_ip != "127.0.0.2" { let _ = analytics.record_query(&domain, true, 0, &client_ip).await; } return Some(resp);
    }

    // Safe Search Enforcement — intercept DNS and return the safe-search IP
    // This forces Google/YouTube/Bing/DDG into restricted mode network-wide.
    if safe_search_on && qtype == dns_parser::QueryType::A {
        let safe_ip: Option<[u8; 4]> = match base_domain {
            "google.com" | "google.co.in" | "google.co.uk" | "google.com.au"
            | "google.ca" | "google.de" | "google.fr" | "google.co.jp" => {
                // forcesafesearch.google.com
                Some([216, 239, 38, 120])
            }
            "youtube.com" => {
                // restrict.youtube.com
                Some([216, 239, 38, 119])
            }
            "bing.com" => {
                // strict.bing.com
                Some([204, 79, 197, 220])
            }
            "duckduckgo.com" => {
                // safe.duckduckgo.com
                Some([52, 149, 24, 70])
            }
            _ => None,
        };

        if let Some(ip) = safe_ip {
            let mut resp = packet_data[0..offset].to_vec();
            resp[2] |= 0x80; // QR=1
            resp[3] |= 0x80; // RA=1
            resp[3] &= 0xF0; // NOERROR
            resp[8] = 0; resp[9] = 0;
            resp[10] = 0; resp[11] = 0;
            resp[6] = 0; resp[7] = 1; // ANCOUNT = 1
            resp.extend_from_slice(&[
                0xC0, 0x0C,       // Name: pointer to question
                0x00, 0x01,       // Type: A
                0x00, 0x01,       // Class: IN
                0x00, 0x00, 0x00, 0x3C, // TTL: 60s
                0x00, 0x04,       // RDLENGTH: 4
                ip[0], ip[1], ip[2], ip[3],
            ]);
            if client_ip != "127.0.0.2" { let _ = analytics.record_query(&domain, false, 0, &client_ip).await; } return Some(resp);
        }
    }

    // Cache check
    let qtype_u16 = qtype as u16;
    if let Some((mut cached_bytes, expires_at)) = cache.get(&(domain.clone(), qtype_u16)).await {
        if Instant::now() <= expires_at {
            cached_bytes[0] = packet_data[0];
            cached_bytes[1] = packet_data[1];
            if client_ip != "127.0.0.2" { let _ = analytics.record_cache_hit(&domain, &client_ip).await; } return Some(cached_bytes);
        } else {
            cache.invalidate(&(domain.clone(), qtype_u16)).await;
        }
    }

    let start_time = Instant::now();

    // Fallback: Encrypted DoH to Quad9 for whitelisted-but-broken domains
    if fallback.read().await.check_fallback(&domain).is_some() {
        match http_client.post("https://dns.quad9.net/dns-query")
            .header("accept", "application/dns-message")
            .header("content-type", "application/dns-message")
            .body(packet_data.clone())
            .send().await
        {
            Ok(resp) => {
                if let Ok(bytes) = resp.bytes().await {
                    let latency = start_time.elapsed().as_millis() as u32;
                    if client_ip != "127.0.0.2" { let _ = analytics.record_query(&domain, false, latency, &client_ip).await; } return Some(bytes.to_vec());
                }
            }
            Err(e) => {
                tracing::warn!("DoH fallback failed for {}: {}", domain, e);
                // Fall through to normal upstream
            }
        }
    }

    // Ultra-Robust Upstream Resolution: Primary (Unbound) -> Quad9 -> Google
    let _permit = semaphore.acquire().await.unwrap();
    let upstreams = [upstream_addr.as_str(), "9.9.9.9:53", "8.8.8.8:53"];
    let mut recv_buf = vec![0u8; 4096];
    let mut size = 0;
    let mut success = false;

    for &up_addr in &upstreams {
        let upstream_socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => continue, // Try next upstream
        };

        if upstream_socket.connect(up_addr).await.is_err() {
            continue;
        }

        if upstream_socket.send(&packet_data).await.is_err() {
            continue;
        }

        // 2-second strict timeout per upstream to ensure lightning fast failover
        if let Ok(Ok(n)) = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            upstream_socket.recv(&mut recv_buf)
        ).await {
            if n > 0 {
                size = n;
                success = true;
                break; // Successfully got an answer
            }
        } else {
            tracing::warn!("Upstream DNS timeout/fail ({}) for {}", up_addr, domain);
        }
    }

    if !success || size == 0 {
        tracing::error!("ALL upstreams failed for {}", domain);
        let resp = make_servfail(&packet_data, offset);
        return Some(resp);
    }

    // Inspect upstream response for security threats
    let mut is_malicious = false;
    let mut min_ttl = 300u32;
    if let Ok(resp_packet) = Packet::parse(&recv_buf[..size]) {
        for answer in &resp_packet.answers {
            if answer.ttl < min_ttl {
                min_ttl = answer.ttl;
            }
            if !is_explicitly_allowed {
                // CNAME cloaking: check CNAME target against policy and blocklist
                if let dns_parser::RData::CNAME(cname) = &answer.data {
                    let cname_str = cname.0.to_string();
                    if let PolicyDecision::Blocked(_) = policy.read().await.evaluate(&cname_str, Some(&client_ip)) {
                        is_malicious = true;
                        break;
                    }
                    if blocklist.read().await.is_blocked(&cname_str) {
                        is_malicious = true;
                        break;
                    }
                }
            }
            // DNS rebinding protection & Fast-Flux
            match &answer.data {
                dns_parser::RData::A(ip) => {
                    let o = ip.0.octets();
                    let is_private = o[0] == 127 || o[0] == 10
                        || (o[0] == 172 && o[1] >= 16 && o[1] <= 31)
                        || (o[0] == 192 && o[1] == 168);
                    if is_private && !domain.ends_with(".local") && domain != "localhost" {
                        tracing::warn!("DNS rebinding attempt blocked: {} -> {:?}", domain, ip.0);
                        is_malicious = true;
                        break;
                    }
                    
                    let mut ff = fast_flux.write().await;
                    ff.record_resolution(&domain, std::net::IpAddr::V4(ip.0));
                    if ff.is_fast_flux(&domain) {
                        tracing::warn!("Fast-flux detected for domain: {}", domain);
                        is_malicious = true;
                        break;
                    }
                }
                dns_parser::RData::AAAA(ip) => {
                    let segs = ip.0.segments();
                    let is_private = ip.0.is_loopback() || (segs[0] & 0xfe00) == 0xfc00;
                    if is_private && !domain.ends_with(".local") && domain != "localhost" {
                        tracing::warn!("DNS rebinding attempt blocked (AAAA): {} -> {:?}", domain, ip.0);
                        is_malicious = true;
                        break;
                    }
                    
                    let mut ff = fast_flux.write().await;
                    ff.record_resolution(&domain, std::net::IpAddr::V6(ip.0));
                    if ff.is_fast_flux(&domain) {
                        tracing::warn!("Fast-flux detected for domain: {}", domain);
                        is_malicious = true;
                        break;
                    }
                }
                _ => {}
            }
        }
    }

    if is_malicious {
        let resp = make_blocked_resp(&packet_data, offset, qtype);
        if client_ip != "127.0.0.2" {
            let _ = analytics.record_query(&domain, true, 0, &client_ip).await;
        }
        return Some(resp);
    } else {
        let mut final_ttl = min_ttl;
        if final_ttl > 300 { final_ttl = 300; }
        if final_ttl < 5 { final_ttl = 5; }
        
        let expires_at = Instant::now() + Duration::from_secs(final_ttl as u64);
        cache.insert((domain.clone(), qtype as u16), (recv_buf[..size].to_vec(), expires_at)).await;

        let latency = start_time.elapsed().as_millis() as u32;
        if client_ip != "127.0.0.2" { let _ = analytics.record_query(&domain, false, latency, &client_ip).await; } return Some(recv_buf[..size].to_vec());
    }

}
