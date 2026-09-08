use std::{collections::{HashMap, HashSet}, sync::Arc, time::{Duration, Instant}};
use tokio::sync::RwLock;

/// Bounded rate guard. This is DNS containment, not a network firewall.
pub struct AnomalyDetector {
    pub quarantined: Arc<RwLock<HashSet<String>>>,
    windows: tokio::sync::Mutex<HashMap<String, (Instant, u32)>>,
    expiry: tokio::sync::Mutex<HashMap<String, Instant>>,
}
impl AnomalyDetector {
    pub fn new() -> Self {
        Self { quarantined:Default::default(), windows:Default::default(), expiry:Default::default() }
    }
    pub async fn check_and_record(&self, client: &str) -> bool {
        let now = Instant::now();
        // One fixed lock order: expiry -> quarantine -> windows. No unbounded timestamp lists.
        let mut expiry = self.expiry.lock().await;
        let mut quarantined = self.quarantined.write().await;
        expiry.retain(|ip, deadline| { if *deadline <= now { quarantined.remove(ip); false } else { true } });
        if quarantined.contains(client) { return true; }
        let mut windows = self.windows.lock().await;
        windows.retain(|_, (start, _)| now.duration_since(*start) < Duration::from_secs(60));
        if windows.len() >= 10_000 && !windows.contains_key(client) { return true; }
        let count = windows.entry(client.into()).or_insert((now, 0));
        count.1 = count.1.saturating_add(1);
        // Conservative rate guard applies to LAN, VPN and loopback alike, expires automatically.
        if count.1 > 12_000 {
            quarantined.insert(client.into()); expiry.insert(client.into(), now + Duration::from_secs(60));
            windows.remove(client);
            tracing::warn!("DNS rate guard active for {} for 60 seconds (not network isolation)", client);
            return true;
        }
        false
    }
    pub async fn unquarantine(&self, client: &str) {
        let mut expiry = self.expiry.lock().await;
        expiry.remove(client);
        self.quarantined.write().await.remove(client);
        self.windows.lock().await.remove(client);
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[tokio::test] async fn vpn_clients_are_not_exempt_and_release_resets_window() {
        let d = AnomalyDetector::new();
        for _ in 0..12_000 { assert!(!d.check_and_record("100.64.0.1").await); }
        assert!(d.check_and_record("100.64.0.1").await);
        d.unquarantine("100.64.0.1").await;
        assert!(!d.check_and_record("100.64.0.1").await);
    }
}
