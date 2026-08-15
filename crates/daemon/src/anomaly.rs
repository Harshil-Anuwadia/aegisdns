use std::collections::{VecDeque, HashSet};
use std::time::{Instant, Duration};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct AnomalyDetector {
    pub quarantined: Arc<RwLock<HashSet<String>>>,
    // client_ip -> VecDeque of query timestamps
    history: Arc<RwLock<std::collections::HashMap<String, VecDeque<Instant>>>>,
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            quarantined: Arc::new(RwLock::new(HashSet::new())),
            history: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    pub async fn check_and_record(&self, client_ip: &str) -> bool {
        let now = Instant::now();
        
        // Check if already quarantined
        if self.quarantined.read().await.contains(client_ip) {
            return true;
        }

        let mut history = self.history.write().await;
        let dq = history.entry(client_ip.to_string()).or_insert_with(VecDeque::new);
        dq.push_back(now);

        // cleanup old > 10 mins (600 seconds)
        while let Some(&t) = dq.front() {
            if now.duration_since(t) > Duration::from_secs(600) {
                dq.pop_front();
            } else {
                break;
            }
        }

        // queries in last 60s
        let mut last_60s_count = 0;
        let mut older_count = 0;
        
        for &t in dq.iter() {
            if now.duration_since(t) <= Duration::from_secs(60) {
                last_60s_count += 1;
            } else {
                older_count += 1;
            }
        }

        // 9 minutes = 540 seconds. Average per minute for the previous 9 mins:
        let avg_per_min = older_count as f64 / 9.0;
        
        // Whitelist safe internal networks (Docker bridge, Tailscale, Localhost)
        if client_ip.starts_with("127.") || client_ip.starts_with("172.") || client_ip.starts_with("100.") {
            return false;
        }

        // If a device suddenly makes >2500 queries in 60 seconds OR >20x its normal rate
        if last_60s_count > 2500 || (avg_per_min > 5.0 && last_60s_count as f64 > avg_per_min * 20.0) {
            tracing::warn!("Anomaly detected for IP {}. Quarantining.", client_ip);
            self.quarantined.write().await.insert(client_ip.to_string());
            return true;
        }

        false
    }

    #[allow(dead_code)]
    pub async fn is_quarantined(&self, client_ip: &str) -> bool {
        self.quarantined.read().await.contains(client_ip)
    }

    #[allow(dead_code)]
    pub async fn unquarantine(&self, client_ip: &str) {
        self.quarantined.write().await.remove(client_ip);
    }
}
