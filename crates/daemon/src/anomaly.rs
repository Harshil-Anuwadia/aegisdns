use std::{collections::HashSet, sync::{Arc, Mutex}, time::{Duration, Instant}};
use moka::future::Cache;
use tokio::sync::RwLock;

#[derive(Debug)]
struct ClientWindow {
    started: Instant,
    count: u32,
    quarantine_until: Option<Instant>,
}

/// Bounded, per-client rate guard. This is DNS containment, not a network firewall.
pub struct AnomalyDetector {
    pub quarantined: Arc<RwLock<HashSet<String>>>,
    clients: Cache<String, Arc<Mutex<ClientWindow>>>,
}
impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            quarantined: Default::default(),
            clients: Cache::builder()
                .max_capacity(10_000)
                .time_to_idle(Duration::from_secs(5 * 60))
                .build(),
        }
    }
    pub async fn check_and_record(&self, client: &str) -> bool {
        let now = Instant::now();
        let entry = self.clients.get_with(client.to_owned(), async move {
            Arc::new(Mutex::new(ClientWindow { started: now, count: 0, quarantine_until: None }))
        }).await;

        let (blocked, became_quarantined, expired) = {
            let mut window = entry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let expired = window.quarantine_until.is_some_and(|deadline| deadline <= now);
            if expired {
                window.quarantine_until = None;
                window.started = now;
                window.count = 0;
            }
            if window.quarantine_until.is_some() {
                (true, false, expired)
            } else {
                if now.duration_since(window.started) >= Duration::from_secs(60) {
                    window.started = now;
                    window.count = 0;
                }
                window.count = window.count.saturating_add(1);
                if window.count > 12_000 {
                    window.count = 0;
                    window.quarantine_until = Some(now + Duration::from_secs(60));
                    (true, true, expired)
                } else {
                    (false, false, expired)
                }
            }
        };

        // The dashboard set changes only on transitions; normal queries never take its lock.
        if became_quarantined {
            self.quarantined.write().await.insert(client.to_owned());
            tracing::warn!("DNS rate guard active for {} for 60 seconds (not network isolation)", client);
        } else if expired {
            self.quarantined.write().await.remove(client);
        }
        blocked
    }
    pub async fn unquarantine(&self, client: &str) {
        self.clients.invalidate(client).await;
        self.quarantined.write().await.remove(client);
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
