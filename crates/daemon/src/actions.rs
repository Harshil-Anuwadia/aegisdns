use analytics::{AnalyticsDb, CustomAction};
use moka::sync::Cache;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

// ── Process-level moka cache (hot path for DNS) ───────────────────────────────
static ACTION_CACHE: OnceLock<Cache<String, Option<CustomAction>>> = OnceLock::new();

fn cache() -> &'static Cache<String, Option<CustomAction>> {
    ACTION_CACHE.get_or_init(|| {
        Cache::builder()
            .max_capacity(1_000)
            .time_to_live(Duration::from_secs(30))
            .build()
    })
}


/// Full lookup that hits SQLite when the cache has no entry.
pub fn get_action_for_domain_db(domain: &str, db: &Arc<AnalyticsDb>) -> Option<CustomAction> {
    if let Some(cached) = cache().get(domain) {
        return cached;
    }
    let result = db.get_action(domain);
    cache().insert(domain.to_string(), result.clone());
    result
}

/// Invalidate a single domain from the cache (call after any write).
pub fn invalidate(domain: &str) {
    cache().invalidate(domain);
}


