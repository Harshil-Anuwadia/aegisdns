use std::sync::Arc;
use tokio::sync::RwLock;
use proxy::DnsProxy;
mod proxy;
mod actions;
mod anomaly;
mod web;
mod device_registry;
mod telegram;
mod dhcp;
mod auth;
mod tailscale;
mod upstream;
mod relationships;
mod privacy;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    std::fs::create_dir_all(config::paths::get_data_dir())?;
    auth::initialize()?;
    let analytics=Arc::new(analytics::AnalyticsDb::new(config::paths::get_db_path())?);
    let action_domains=actions::ActionDomains::load(&analytics)?;
    let policy_existed=config::paths::get_policy_path().exists();
    let mut pol=policy::PolicyEngine::load_or_default();
    if !policy_existed { // Migrate once; never overwrite scoped rules from the legacy global table.
        if let Ok((allowed,denied))=analytics.load_policy_rules() {
            for d in allowed {pol.allow(d);} for d in denied {pol.deny(d);}
        }
        pol.save()?;
    }
    let policy=Arc::new(RwLock::new(pol));
    let blocklists=Arc::new(RwLock::new(blocklist::BlocklistManager::new()));
    let anomaly=Arc::new(anomaly::AnomalyDetector::new());
    let fast_flux=Arc::new(RwLock::new(risk::FastFluxDetector::new()));
    let cache=moka::future::Cache::builder().max_capacity(50_000).time_to_live(std::time::Duration::from_secs(300)).build();
    let devices=Arc::new(RwLock::new(device_registry::DeviceRegistry::load()));
    let telegram=Arc::new(RwLock::new(telegram::load_config()));
    let upstream=upstream::load_config().await;
    let privacy=Arc::new(privacy::PrivacyGuard::load());
    if let Ok(summaries)=analytics.privacy_summaries().await {privacy.seed(&summaries);}
    let ip_metadata=relationships::IpMetadata::load();
    let host_ip=load_host_ip();
    let restart=Arc::new(tokio::sync::Notify::new());
    let mut services=tokio::task::JoinSet::new();

    #[cfg(unix)]
    services.spawn(async {
        loop {
            let mut manager=resolver::UnboundManager::new();
            let initial=config::upstream::UpstreamDnsConfig::load().unwrap_or_default();
            if let Err(e)=manager.start().await {tracing::error!("Unbound startup failed: {}",e);}
            if let Some(mut child)=manager.process.take() {
                loop {
                    tokio::select! {
                        result=child.wait()=>{tracing::error!("Unbound exited: {:?}",result);break;}
                        _=tokio::time::sleep(std::time::Duration::from_secs(2))=>{
                            if let Ok(current)=config::upstream::UpstreamDnsConfig::load() {
                                if current!=initial {tracing::info!("Reloading validated upstream configuration");let _=child.kill().await;break;}
                            }
                        }
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
    #[cfg(windows)]
    {
        let mut manager=resolver::UnboundManager::new();
        manager.start().await?;
    }
    let refresh=blocklists.clone();
    services.spawn(async move {
        // Run at boot and every six hours. Failed updates keep the active snapshot.
        loop {
            {
                let _update=blocklist::UPDATE_LOCK.lock().await;
                let lists=refresh.read().await.get_lists();
                match blocklist::BlocklistManager::download_lists(lists).await {
                    Ok((lists,domains,exceptions))=>{refresh.write().await.apply_update(lists,domains,exceptions);tracing::info!("Blocklist snapshot refreshed");}
                    Err(e)=>tracing::error!("Blocklist refresh failed; last-known-good protection retained: {}",e),
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(6*3600)).await;
        }
    });
    for addr in std::env::var("AEGIS_DNS_LISTEN").unwrap_or_else(|_|"0.0.0.0:53,[::]:53".into()).split(',') {
        let _:std::net::SocketAddr=addr.parse()?;
        let proxy=DnsProxy::new(addr,resolver::proxy_upstream_addr(),&host_ip,analytics.clone(),action_domains.clone(),policy.clone(),blocklists.clone(),fast_flux.clone(),anomaly.clone(),cache.clone(),telegram.clone(),devices.clone(),upstream.clone(),privacy.clone(),ip_metadata.clone());
        services.spawn(async move {loop {
            if let Err(e)=proxy.clone().run().await {tracing::error!("DNS listener failed: {}",e);}
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }});
    }
    let action_db=analytics.clone();
    let action_host_ip=host_ip.clone();
    services.spawn(async move {loop {
        if let Err(e)=web::start_action_server(action_db.clone(),&action_host_ip).await {tracing::error!("Action API failed: {}",e);}
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }});
    let web_db=analytics.clone();
    let dhcp_devices=devices.clone();
    let web_restart=restart.clone();
    let web_privacy=privacy.clone();
    services.spawn(async move {loop {
        if let Err(e)=web::start_web_server(web_db.clone(),action_domains.clone(),policy.clone(),blocklists.clone(),anomaly.clone(),cache.clone(),devices.clone(),telegram.clone(),upstream.clone(),web_privacy.clone(),web_restart.clone()).await {tracing::error!("Dashboard failed: {}",e);}
        tokio::time::sleep(std::time::Duration::from_secs(5)).await;
    }});
    let prune=analytics.clone();
    services.spawn(async move {loop {
        tokio::time::sleep(std::time::Duration::from_secs(86400)).await;
        let db=prune.clone();
        let _=tokio::task::spawn_blocking(move ||db.cleanup_old_queries()).await;
    }});
    // DHCP owns a plain blocking thread; capture its runtime handle while inside Tokio.
    dhcp::start_dhcp_server(dhcp::load_config(),dhcp_devices);
    tokio::select! {
        _=shutdown_signal()=>tracing::info!("Shutdown requested"),
        _=restart.notified()=>tracing::info!("Graceful restart requested"),
        result=services.join_next()=>tracing::error!("Service unexpectedly stopped: {:?}",result),
    }
    services.abort_all();
    while services.join_next().await.is_some() {}
    analytics.flush().await?;
    Ok(())
}

/// Resolve the address this host answers with for blocked pages and actions.
///
/// `AEGIS_HOST_IP` wins, then the first usable `host_ips` entry from
/// `config.json`, then loopback. The config file is located through
/// `config::config_candidates()` so the daemon, the resolver and the
/// container bind-mount all agree on which file is authoritative.
fn load_host_ip()->String {
    // Compose passes `AEGIS_HOST_IP: ${AEGIS_HOST_IP:-}`, so an unset variable
    // arrives as an empty string; that is "not configured", not an error.
    match std::env::var("AEGIS_HOST_IP").unwrap_or_default().trim() {
        "" => {}
        // An explicit loopback override is honoured: it is a deliberate choice
        // on single-machine installs, unlike an accidental loopback in host_ips.
        value => match value.parse::<std::net::Ipv4Addr>() {
            Ok(ip) if usable_host_ip(&ip) || ip.is_loopback() => return ip.to_string(),
            _ => tracing::warn!("Ignoring AEGIS_HOST_IP={value:?}: not a usable unicast IPv4 address"),
        },
    }
    let Some(config)=config::load_main_config() else {return "127.0.0.1".into()};
    config.host_ips.iter()
        .filter_map(|ip|ip.trim().parse::<std::net::Ipv4Addr>().ok())
        .find(usable_host_ip)
        .map(|ip|ip.to_string())
        .unwrap_or_else(||{
            tracing::warn!("config.json has no usable non-loopback host_ips entry; blocked pages will point at 127.0.0.1");
            "127.0.0.1".into()
        })
}

/// A host IP must be a routable unicast address; loopback, multicast,
/// broadcast and the unspecified address cannot serve a blocked page.
fn usable_host_ip(ip:&std::net::Ipv4Addr)->bool {
    !ip.is_loopback()&&!ip.is_multicast()&&!ip.is_broadcast()&&!ip.is_unspecified()
}
async fn shutdown_signal() {
    #[cfg(unix)] {
        let mut term=tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()).expect("SIGTERM handler");
        tokio::select!{_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    }
    #[cfg(not(unix))] {let _=tokio::signal::ctrl_c().await;}
}
