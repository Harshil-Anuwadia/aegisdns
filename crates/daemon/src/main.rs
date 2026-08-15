use std::sync::Arc;
use tokio::sync::RwLock;

mod proxy;
mod actions;
mod anomaly;
use proxy::DnsProxy;
mod web;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    tracing::info!("Starting AegisDNS daemon");

    // Initialize configuration
    let _config = config::AegisConfig::default();

    // Start Unbound process manager with auto-restart
    tokio::spawn(async move {
        loop {
            let mut unbound = resolver::UnboundManager::new();
            if let Err(e) = unbound.start().await {
                tracing::error!("Failed to start unbound: {}", e);
            } else {
                tracing::info!("Unbound resolver started");
            }
            // Wait for unbound to crash/exit
            if let Some(mut child) = unbound.process.take() {
                let _ = child.wait().await;
            }
            tracing::error!("Unbound crashed! Auto-restarting in 5 seconds...");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }
    });

    // Initialize Analytics Database in persistent storage
    let db_dir = config::paths::get_data_dir();
    std::fs::create_dir_all(&db_dir)?;
    let db_path = config::paths::get_db_path();
    let analytics_db = Arc::new(analytics::AnalyticsDb::new(db_path)?);

    // Initialize Policy Engine from persistent storage
    let mut pol = policy::PolicyEngine::load_or_default();
    if let Ok((allowed, denied)) = analytics_db.load_policy_rules() {
        for d in allowed { pol.allow(d); }
        for d in denied { pol.deny(d); }
    }
    let policy_engine = Arc::new(RwLock::new(pol));

    // Initialize Blocklist Manager and start initial sync
    let manager = blocklist::BlocklistManager::new();
    let blocklist_manager = Arc::new(RwLock::new(manager));
    let bl_clone = blocklist_manager.clone();
    tokio::spawn(async move {
        // Wait for Unbound and networking to fully initialize on boot
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        
        let should_download = {
            let bl = bl_clone.read().await;
            bl.compiled_domains.is_empty()
        };

        if should_download {
            tracing::info!("Downloading and compiling blocklists...");
            let lists = bl_clone.read().await.get_lists();
            match blocklist::BlocklistManager::download_lists(lists).await {
                Ok((new_lists, new_compiled)) => {
                    bl_clone.write().await.apply_update(new_lists, new_compiled);
                    tracing::info!("Blocklists compiled successfully.");
                }
                Err(e) => {
                    tracing::error!("Failed to update blocklists: {}", e);
                }
            }
        } else {
            tracing::info!("Blocklist cache loaded from disk. Skipping download on boot.");
        }
    });
    let bl_threat_clone = blocklist_manager.clone();
    tokio::spawn(async move {
        loop {
            let threats = blocklist::BlocklistManager::fetch_realtime_threats().await;
            if !threats.is_empty() {
                bl_threat_clone.write().await.apply_realtime_threats(threats);
            }
            tokio::time::sleep(std::time::Duration::from_secs(1800)).await; // every 30 mins
        }
    });

    // Initialize Fallback Engine
    let fallback_engine = Arc::new(RwLock::new(fallback::FallbackEngine::new()));

    // Initialize Fast-Flux Detector
    let fast_flux_detector = Arc::new(RwLock::new(risk::FastFluxDetector::new()));

    // Initialize Anomaly Detector
    let anomaly_detector = Arc::new(anomaly::AnomalyDetector::new());

    // Upstream resolver (Unbound running locally)
    #[cfg(unix)]
    let upstream = "127.0.0.1:5353";
    #[cfg(windows)]
    let upstream = "8.8.8.8:53";

    // Create global shared DNS Cache
    let global_cache = moka::future::Cache::builder()
        .time_to_live(std::time::Duration::from_secs(300))
        .build();

    // Bind DNS proxy to ALL interfaces on port 53.
    // This covers: 127.0.0.1 (local PC), 10.x.x.x (LAN), 100.x.x.x (Tailscale)
    // with a single, simple, stable binding — no polling loop needed.
    let p_db = analytics_db.clone();
    let p_pol = policy_engine.clone();
    let p_bl = blocklist_manager.clone();
    let p_fb = fallback_engine.clone();
    let p_ff = fast_flux_detector.clone();
    let p_anom = anomaly_detector.clone();
    let p_cache = global_cache.clone();
    tokio::spawn(async move {
        loop {
            let p = DnsProxy::new("0.0.0.0:53", upstream, p_db.clone(), p_pol.clone(), p_bl.clone(), p_fb.clone(), p_ff.clone(), p_anom.clone(), p_cache.clone());
            if let Err(e) = p.run().await {
                tracing::error!("DNS Proxy crashed: {}. Restarting in 5s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    });

    // Start Web Dashboard backend
    let web_analytics = analytics_db.clone();
    let web_policy = policy_engine.clone();
    let web_blocklist = blocklist_manager.clone();
    let web_fallback = fallback_engine.clone();
    let web_anomaly = anomaly_detector.clone();
    let web_cache = global_cache.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = web::start_web_server(
                web_analytics.clone(), web_policy.clone(),
                web_blocklist.clone(), web_fallback.clone(),
                web_anomaly.clone(), web_cache.clone()
            ).await {
                tracing::error!("Web UI Server crashed: {}. Restarting in 5s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    });

    // Start Block Page server on port 80
    let bp_analytics = analytics_db.clone();
    let bp_policy = policy_engine.clone();
    let bp_blocklist = blocklist_manager.clone();
    tokio::spawn(async move {
        loop {
            if let Err(e) = web::start_block_page_server(bp_analytics.clone(), bp_policy.clone(), bp_blocklist.clone()).await {
                tracing::error!("Block Page server crashed: {}. Restarting in 5s...", e);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
        }
    });

    // Background: Realtime Threat Feed Refresh (every 30 minutes)
    let threat_bl = blocklist_manager.clone();
    tokio::spawn(async move {
        // Wait for initial blocklist download to complete first
        tokio::time::sleep(std::time::Duration::from_secs(45)).await;
        loop {
            tracing::info!("Refreshing realtime threat intelligence feeds...");
            let new_threats = blocklist::BlocklistManager::fetch_realtime_threats().await;
            threat_bl.write().await.apply_realtime_threats(new_threats);
            tokio::time::sleep(std::time::Duration::from_secs(1800)).await;
        }
    });

    // Background: Analytics DB pruning (every 24 hours)
    let prune_db = analytics_db.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
            tracing::info!("Running automated database pruning...");
            if let Err(e) = prune_db.cleanup_old_queries() {
                tracing::error!("Failed to prune old queries: {}", e);
            }
        }
    });

    // Graceful shutdown on Ctrl+C / SIGTERM
    tokio::signal::ctrl_c().await?;
    tracing::info!("Shutting down AegisDNS");
    Ok(())
}
