#[cfg(test)]
mod tests {
    use crate::proxy::DnsProxy;
    use analytics::AnalyticsDb;
    use policy::PolicyEngine;
    use blocklist::BlocklistManager;
    use fallback::FallbackEngine;
    
    use tokio::net::UdpSocket;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    // A simple function to generate a raw DNS A-record query for testing
    fn build_dns_query(domain: &str) -> Vec<u8> {
        let mut builder = dns_parser::Builder::new_query(1, true);
        builder.add_question(domain, false, dns_parser::QueryType::A, dns_parser::QueryClass::IN);
        builder.build().unwrap_or_default()
    }

    #[tokio::test]
    async fn test_dns_proxy_integration() {
        // Setup Temporary Analytics DB
        let db_path = std::env::temp_dir().join(format!("test_analytics_{}.db", std::process::id()));
        let analytics_db = Arc::new(AnalyticsDb::new(db_path.clone()).unwrap());

        // Setup Policy Engine
        let mut policy_engine = PolicyEngine::load_or_default();
        policy_engine.deny("blocked.example.com".into());
        policy_engine.allow("allowed.example.com".into());
        let policy_engine = Arc::new(RwLock::new(policy_engine));

        // Setup Blocklist Manager
        let blocklist_manager = BlocklistManager::new();
        let blocklist_manager = Arc::new(RwLock::new(blocklist_manager));

        // Setup Fallback Engine
        let mut fallback = FallbackEngine::new();
        fallback.add_fallback("fallback.example.com".into(), fallback::FallbackMode::Permanent);
        let fallback_engine = Arc::new(RwLock::new(fallback));

        // Start Mock Upstream DNS Server (Echoes back the query for allowed requests)
        let upstream_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_socket.local_addr().unwrap().to_string();
        tokio::spawn(async move {
            let mut buf = [0u8; 512];
            loop {
                if let Ok((len, src)) = upstream_socket.recv_from(&mut buf).await {
                    let _ = upstream_socket.send_to(&buf[..len], src).await;
                }
            }
        });

        // Start DNS Proxy
        let proxy_port = 55353;
        let proxy_addr = format!("127.0.0.1:{}", proxy_port);
        let proxy = DnsProxy::new(&proxy_addr, &upstream_addr, analytics_db.clone(), policy_engine.clone(), blocklist_manager.clone(), fallback_engine.clone());
        
        tokio::spawn(async move {
            let _ = proxy.run().await;
        });
        
        // Give the proxy a moment to bind
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Test Client Socket
        let client_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        
        // 1. Test Blocked Domain (Should return 127.0.0.1 A Record locally)
        let blocked_query = build_dns_query("blocked.example.com");
        client_socket.send_to(&blocked_query, &proxy_addr).await.unwrap();
        
        let mut resp_buf = [0u8; 512];
        let (len, _) = tokio::time::timeout(tokio::time::Duration::from_secs(1), client_socket.recv_from(&mut resp_buf)).await.unwrap().unwrap();
        
        let packet = dns_parser::Packet::parse(&resp_buf[..len]).unwrap();
        assert_eq!(packet.answers.len(), 1, "Blocked domain should return 1 synthetic answer");
        match &packet.answers[0].data {
            dns_parser::RData::A(record) => {
                assert_eq!(record.0, std::net::Ipv4Addr::new(127, 0, 0, 1), "Blocked domain should point to 127.0.0.1 block page");
            },
            _ => panic!("Expected A record for blocked domain"),
        }

        // 2. Test Allowed Domain (Should be forwarded upstream)
        let allowed_query = build_dns_query("allowed.example.com");
        client_socket.send_to(&allowed_query, &proxy_addr).await.unwrap();
        let (len, _) = tokio::time::timeout(tokio::time::Duration::from_secs(1), client_socket.recv_from(&mut resp_buf)).await.unwrap().unwrap();
        
        let packet = dns_parser::Packet::parse(&resp_buf[..len]).unwrap();
        assert_eq!(packet.answers.len(), 0, "Allowed domain should return raw upstream response (0 answers from echo mock)");

        // 3. Test Fallback Override Domain
        let fallback_query = build_dns_query("fallback.example.com");
        client_socket.send_to(&fallback_query, &proxy_addr).await.unwrap();
        // Since upstream for fallback is hardcoded to 8.8.8.8 and it will time out or succeed depending on network, we just ensure it didn't crash.
        
        // 4. Test Analytics Persistence
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let stats = analytics_db.get_stats().await.unwrap();
        assert!(stats.queries_today >= 2, "Analytics should record at least 2 queries");
        assert!(stats.blocked_today >= 1, "Analytics should record at least 1 blocked query");
        assert!(stats.allowed_today >= 1, "Analytics should record at least 1 allowed query");

        // Cleanup
        let _ = std::fs::remove_file(db_path);
    }
}
