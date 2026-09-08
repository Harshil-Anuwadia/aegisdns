pub use config::upstream::UpstreamDnsConfig;
use std::sync::Arc;
use tokio::sync::RwLock;
pub type SharedUpstreamDns = Arc<RwLock<UpstreamDnsConfig>>;
pub async fn load_config() -> SharedUpstreamDns {
    let cfg = UpstreamDnsConfig::load().unwrap_or_else(|e| {
        tracing::error!("Invalid upstream configuration; retaining validated local recursion: {}", e);
        UpstreamDnsConfig::default()
    });
    Arc::new(RwLock::new(cfg))
}
pub async fn save_config(config: &UpstreamDnsConfig) -> anyhow::Result<()> {
    config.validate()?;
    config::atomic_write(config::paths::get_data_dir().join("upstream.json"), serde_json::to_vec_pretty(config)?)?;
    Ok(())
}
