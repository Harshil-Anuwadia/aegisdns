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
use std::time::Instant;

pub struct DnsProxy {
    listen_addr: String,
    upstream_addr: String,
    analytics: Arc<AnalyticsDb>,
    policy: Arc<RwLock<PolicyEngine>>,
    blocklist: Arc<RwLock<BlocklistManager>>,
    fallback: Arc<RwLock<FallbackEngine>>,
    http_client: reqwest::Client,
}

impl DnsProxy {
    pub fn new(listen: &str, upstream: &str, analytics: Arc<AnalyticsDb>, policy: Arc<RwLock<PolicyEngine>>, blocklist: Arc<RwLock<BlocklistManager>>, fallback: Arc<RwLock<FallbackEngine>>) -> Self {
        Self {
            listen_addr: listen.to_string(),
            upstream_addr: upstream.to_string(),
            analytics,
            policy,
            blocklist,
            fallback,
            // Always set timeouts to prevent hung tasks from leaking resources
            http_client: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .connect_timeout(std::time::Duration::from_secs(3))
                .build()
                .unwrap_or_else(|_| reqwest::Client::new()),
        }
    }

    pub async fn run(self) -> anyhow::Result<()> {
        let socket = Arc::new(UdpSocket::bind(&self.listen_addr).await?);
        
        tracing::info!("DNS Proxy listening on {} and forwarding to {}", self.listen_addr, self.upstream_addr);

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
            let upstream_addr = self.upstream_addr.clone();
            let analytics = self.analytics.clone();
            let policy = self.policy.clone();
            let blocklist = self.blocklist.clone();
            let fallback = self.fallback.clone();
            let http_client = self.http_client.clone();

            tokio::spawn(async move {
                let client_ip = src_addr.ip().to_string();

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

                if domain.is_empty() { return; }
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

                // Helper: build a blocked (NXDOMAIN/zero-IP) response
                let make_blocked_resp = |pkt: &[u8], end: usize, qt: dns_parser::QueryType| -> Vec<u8> {
                    let mut resp = pkt[0..end].to_vec();
                    resp[2] |= 0x80; // QR=1
                    resp[3] |= 0x80; // RA=1
                    resp[3] &= 0xF0; // NOERROR
                    resp[8] = 0; resp[9] = 0;
                    resp[10] = 0; resp[11] = 0;
                    match qt {
                        dns_parser::QueryType::A => {
                            resp[6] = 0; resp[7] = 1;
                            resp.extend_from_slice(&[0xC0,0x0C,0x00,0x01,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x04,127,0,0,1]);
                        }
                        dns_parser::QueryType::AAAA => {
                            resp[6] = 0; resp[7] = 1;
                            resp.extend_from_slice(&[0xC0,0x0C,0x00,0x1C,0x00,0x01,0x00,0x00,0x00,0x00,0x00,0x10,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1]);
                        }
                        _ => { resp[6] = 0; resp[7] = 0; } // NODATA
                    }
                    resp
                };

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
                    let _ = socket.send_to(&resp, src_addr).await;
                    if client_ip != "127.0.0.2" {
                        let _ = analytics.record_query(&domain, true, 0, &client_ip).await;
                    }
                    return;
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
                        let _ = socket.send_to(&resp, src_addr).await;
                        if client_ip != "127.0.0.2" {
                            let _ = analytics.record_query(&domain, false, 0, &client_ip).await;
                        }
                        return;
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
                                let _ = socket.send_to(&bytes, src_addr).await;
                                let latency = start_time.elapsed().as_millis() as u32;
                                if client_ip != "127.0.0.2" {
                                    let _ = analytics.record_query(&domain, false, latency, &client_ip).await;
                                }
                                return;
                            }
                        }
                        Err(e) => {
                            tracing::warn!("DoH fallback failed for {}: {}", domain, e);
                            // Fall through to normal upstream
                        }
                    }
                }

                // Normal UDP forward to upstream (Unbound with DNSSEC)
                let upstream_socket = match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::error!("Failed to bind upstream socket: {}", e);
                        let resp = make_servfail(&packet_data, offset);
                        let _ = socket.send_to(&resp, src_addr).await;
                        return;
                    }
                };

                // Connect to prevent response spoofing from other IPs
                if upstream_socket.connect(&upstream_addr).await.is_err() {
                    let resp = make_servfail(&packet_data, offset);
                    let _ = socket.send_to(&resp, src_addr).await;
                    return;
                }

                if upstream_socket.send(&packet_data).await.is_err() {
                    tracing::warn!("Failed to send query to upstream for {}", domain);
                    let resp = make_servfail(&packet_data, offset);
                    let _ = socket.send_to(&resp, src_addr).await;
                    return;
                }

                let mut recv_buf = vec![0u8; 4096];
                let size = match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    upstream_socket.recv(&mut recv_buf)
                ).await {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        tracing::warn!("Upstream recv error for {}: {}", domain, e);
                        let resp = make_servfail(&packet_data, offset);
                        let _ = socket.send_to(&resp, src_addr).await;
                        return;
                    }
                    Err(_) => {
                        tracing::warn!("Upstream DNS timeout for {}", domain);
                        let resp = make_servfail(&packet_data, offset);
                        let _ = socket.send_to(&resp, src_addr).await;
                        return;
                    }
                };

                if size == 0 {
                    let resp = make_servfail(&packet_data, offset);
                    let _ = socket.send_to(&resp, src_addr).await;
                    return;
                }

                // Inspect upstream response for security threats
                let mut is_malicious = false;
                if let Ok(resp_packet) = Packet::parse(&recv_buf[..size]) {
                    for answer in &resp_packet.answers {
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
                        // DNS rebinding protection: block external domains resolving to private IPs
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
                            }
                            dns_parser::RData::AAAA(ip) => {
                                let segs = ip.0.segments();
                                let is_private = ip.0.is_loopback() || (segs[0] & 0xfe00) == 0xfc00;
                                if is_private && !domain.ends_with(".local") && domain != "localhost" {
                                    tracing::warn!("DNS rebinding attempt blocked (AAAA): {} -> {:?}", domain, ip.0);
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
                    let _ = socket.send_to(&resp, src_addr).await;
                    if client_ip != "127.0.0.2" {
                        let _ = analytics.record_query(&domain, true, 0, &client_ip).await;
                    }
                } else {
                    let _ = socket.send_to(&recv_buf[..size], src_addr).await;
                    let latency = start_time.elapsed().as_millis() as u32;
                    if client_ip != "127.0.0.2" {
                        let _ = analytics.record_query(&domain, false, latency, &client_ip).await;
                    }
                }
            });
        }
    }
}
