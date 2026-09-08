use axum::{
    routing::{get, post, delete, put},
    Router,
    Json,
    extract::{State, ConnectInfo, Query, Path},
};
use std::net::SocketAddr;
use tower_http::services::ServeDir;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use analytics::AnalyticsDb;
use policy::{PolicyEngine, ScheduleRule, ScheduleAction};
use blocklist::BlocklistManager;
use diagnostics::{DiagnosticEngine, DiagnosticReport};
use risk::score_domain;
use std::collections::HashMap;
use moka::future::Cache;
use std::time::Instant;

#[derive(Clone)]
#[allow(dead_code)]
pub struct AppState {
    pub analytics: Arc<AnalyticsDb>,
    pub policy: Arc<RwLock<PolicyEngine>>,
    pub blocklist: Arc<RwLock<BlocklistManager>>,
    pub anomaly: Arc<crate::anomaly::AnomalyDetector>,
    pub cache: Cache<(String, u16), (Vec<u8>, Instant)>,
    pub device_registry: Arc<RwLock<crate::device_registry::DeviceRegistry>>,
    pub telegram_cfg: Arc<RwLock<crate::telegram::TelegramConfig>>,
    pub upstream_cfg: crate::upstream::SharedUpstreamDns,
    pub restart: Arc<tokio::sync::Notify>,
}

pub async fn start_web_server(
    analytics: Arc<AnalyticsDb>,
    policy: Arc<RwLock<PolicyEngine>>,
    blocklist: Arc<RwLock<BlocklistManager>>,
    anomaly: Arc<crate::anomaly::AnomalyDetector>,
    cache: Cache<(String, u16), (Vec<u8>, Instant)>,
    device_registry: Arc<RwLock<crate::device_registry::DeviceRegistry>>,
    telegram_cfg: Arc<RwLock<crate::telegram::TelegramConfig>>,
    upstream_cfg: crate::upstream::SharedUpstreamDns,
    restart: Arc<tokio::sync::Notify>,
) -> anyhow::Result<()> {
    let state = AppState {
        analytics,
        policy,
        blocklist,
        anomaly,
        cache,
        device_registry,
        telegram_cfg,
        upstream_cfg,
        restart,
    };

    let app = Router::new()
        .route("/api/stats", get(get_stats))
        .route("/api/telemetry", get(get_telemetry_handler))
        .route("/api/top-domains", get(get_top_domains))
        .route("/api/top-blocked", get(get_top_blocked))
        .route("/api/classify", post(set_classification))
        .route("/api/recent", get(get_recent))
        .route("/api/live-feed", get(live_feed_stream))
        .route("/api/favicon", get(get_favicon))
        .route("/api/lists", get(get_lists))
        .route("/api/blocklists", post(post_blocklist))
        .route("/api/blocklists/:name", delete(delete_blocklist))
        .route("/api/allow", post(post_allow))
        .route("/api/deny", post(post_deny))
        .route("/api/diagnose", post(post_diagnose))
        .route("/api/policy", get(get_policy))
        .route("/api/policy/remove", post(post_policy_remove))
        .route("/api/devices", get(get_devices).post(post_device))
        .route("/api/devices/:ip", delete(delete_device))
        .route("/api/devices/:ip/profile", put(put_device_profile))
        .route("/api/telegram", get(get_telegram).post(post_telegram))
        .route("/api/telegram/test", post(post_telegram_test))
        .route("/api/telegram/detect", post(post_telegram_detect))
        .route("/api/dhcp", get(get_dhcp).post(post_dhcp))
        .route("/api/export/logs", get(get_export_logs))
        .route("/api/restart", post(post_restart))
        .route("/api/timezone", get(|| async { Json(serde_json::json!({"timezone": std::env::var("TZ").unwrap_or_else(|_|"System local time (UTC on Windows)".into())})) }))
        .route("/api/schedules", get(get_schedules))
        .route("/api/logs", delete(delete_logs))
        .route("/api/schedules", post(post_schedule))
        .route("/api/schedules/:id", delete(delete_schedule))
        .route("/api/schedules/:id/toggle", put(put_schedule_toggle))
        .route("/api/risk", post(post_risk))
        .route("/api/safesearch", get(get_safesearch))
        .route("/api/safesearch", post(post_safesearch))
        .route("/api/me", get(get_my_ip))
        .route("/api/quarantine", get(get_quarantine))
        .route("/api/quarantine/:ip", delete(delete_quarantine))
        .route("/api/actions", get(get_actions))
        .route("/api/actions", post(post_action))
        .route("/api/actions/:domain", delete(delete_action))
        .route("/api/actions/logs", get(get_action_logs).delete(clear_action_logs))
        .route("/api/upstream", get(get_upstream).post(post_upstream))
        .route("/blocked", get(get_blocked_page))
        .route("/logo.png", get(get_logo))
        .fallback_service(ServeDir::new("/usr/share/aegisdns/ui"))
        .layer(axum::middleware::from_fn(crate::auth::auth_middleware))
        .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
        .with_state(state);

    let addr: SocketAddr = std::env::var("AEGIS_WEB_LISTEN").unwrap_or_else(|_|"127.0.0.1:5380".into()).parse()?;
    anyhow::ensure!(addr.ip().is_loopback(), "Admin listener must be loopback; expose it through a TLS reverse proxy or Tailscale Serve");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Web UI server listening on http://{}",addr);
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

#[derive(Serialize)]
struct MyIp { ip: String }

async fn get_my_ip(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Json<MyIp> {
    let ip = normalize_ip(&addr.ip().to_string());
    Json(MyIp { ip })
}

#[allow(dead_code)]
pub async fn start_action_server(
    analytics: Arc<AnalyticsDb>,
    host_ip: &str,
) -> anyhow::Result<()> {
    use axum::{extract::Host, response::IntoResponse};
    let limits = Arc::new(tokio::sync::Semaphore::new(8));
    let app = Router::new().fallback(post(move |Host(host): Host,
        headers: axum::http::HeaderMap, Json(params): Json<HashMap<String,String>>| {
        let analytics = analytics.clone(); let limits = limits.clone();
        async move {
            let host = config::canonical_domain(host.split(':').next().unwrap_or(&host));
            let Some(action) = crate::actions::get_action_for_domain_db(&host, &analytics).await else {
                return (axum::http::StatusCode::NOT_FOUND,"Unknown action").into_response();
            };
            let provided = headers.get("authorization").and_then(|h|h.to_str().ok()).and_then(|h|h.strip_prefix("Bearer ")).unwrap_or("");
            if provided.len() < 32 || !action.token.as_ref().is_some_and(|hash| crate::actions::verify_token(provided, hash)) {
                return (axum::http::StatusCode::UNAUTHORIZED,"A valid action Bearer token is required").into_response();
            }
            let Ok(_permit) = limits.try_acquire_owned() else { return (axum::http::StatusCode::TOO_MANY_REQUESTS,"Action limit reached").into_response(); };
            let result = crate::actions::execute(&action, &params, provided).await;
            match result {
                Ok(body) => {
                    analytics.log_action(&host,"success",Some("Action completed"));
                    let mut response = body.into_response();
                    response.headers_mut().insert(axum::http::header::CONTENT_TYPE,"text/html; charset=utf-8".parse().unwrap());
                    response.headers_mut().insert(axum::http::header::CONTENT_SECURITY_POLICY,"sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'".parse().unwrap());
                    response.headers_mut().insert(axum::http::header::CACHE_CONTROL,"no-store".parse().unwrap());
                    response
                }
                Err(e) => {
                    analytics.log_action(&host,"failed",Some(&e.to_string()));
                    (axum::http::StatusCode::BAD_GATEWAY,"Action failed; see action logs").into_response()
                }
            }
        }
    })).layer(axum::extract::DefaultBodyLimit::max(32 * 1024));
    let addr: SocketAddr = std::env::var("AEGIS_ACTION_LISTEN").unwrap_or_else(|_|format!("{}:5381",host_ip)).parse()?;
    anyhow::ensure!(config::allowed_dns_client(addr.ip()),"Action listener must use a loopback, private LAN, or Tailscale address");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!("Action API listening on {} (authenticated POST only)",addr);
    axum::serve(listener,app).await?;
    Ok(())
}

#[derive(Serialize)]
struct WebStats {
    queries_today: u64,
    blocked_today: u64,
    allowed_today: u64,
    cache_hits: u64,
    avg_latency_ms: f64,
}

fn normalize_ip(ip: &str) -> String {
    if ip == "::1" {
        "127.0.0.1".to_string()
    } else {
        ip.to_string()
    }
}

#[derive(Deserialize)]
struct StatsQuery {
    device_id: Option<String>,
}

async fn get_telemetry_handler(State(state): State<AppState>) -> Json<analytics::Telemetry> {
    if let Ok(telemetry) = state.analytics.get_telemetry().await {
        Json(telemetry)
    } else {
        Json(analytics::Telemetry::default())
    }
}

async fn get_stats(State(state): State<AppState>, ConnectInfo(_addr): ConnectInfo<SocketAddr>, Query(params): Query<StatsQuery>) -> Json<WebStats> {
    let ip = match params.device_id {
        Some(id) if !id.trim().is_empty() => id,
        _ => "".to_string(),
    };

    let stats_result = if ip.is_empty() {
        state.analytics.get_stats().await
    } else {
        state.analytics.get_stats_for_ip(&ip).await
    };

    if let Ok(stats) = stats_result {
        Json(WebStats {
            queries_today: stats.queries_today,
            blocked_today: stats.blocked_today,
            allowed_today: stats.allowed_today,
            cache_hits: stats.cache_hits,
            avg_latency_ms: stats.avg_latency_ms,
        })
    } else {
        Json(WebStats {
            queries_today: 0,
            blocked_today: 0,
            allowed_today: 0,
            cache_hits: 0,
            avg_latency_ms: 0.0,
        })
    }
}

#[derive(Serialize)]
pub struct DomainCount {
    pub domain: String,
    pub count: u64,
}

#[derive(serde::Serialize)]
pub struct AggregatedDomainsResponse {
    pub top_domains: Vec<DomainCount>,
    pub infrastructure: Vec<DomainCount>,
    pub unknown: Vec<DomainCount>,
}

async fn get_top_domains(State(state): State<AppState>, ConnectInfo(_addr): ConnectInfo<SocketAddr>, Query(params): Query<StatsQuery>) -> Json<AggregatedDomainsResponse> {
    let ip = match params.device_id {
        Some(id) if !id.trim().is_empty() => id,
        _ => "".to_string(),
    };

    let domains_result = if ip.is_empty() {
        state.analytics.get_top_domains().await
    } else {
        state.analytics.get_top_domains_for_ip(&ip).await
    };

    if let Ok(agg) = domains_result {
        Json(AggregatedDomainsResponse {
            top_domains: agg.top_domains.into_iter().map(|(d, c)| DomainCount { domain: d, count: c }).collect(),
            infrastructure: agg.infrastructure.into_iter().map(|(d, c)| DomainCount { domain: d, count: c }).collect(),
            unknown: agg.unknown.into_iter().map(|(d, c)| DomainCount { domain: d, count: c }).collect(),
        })
    } else {
        Json(AggregatedDomainsResponse { top_domains: vec![], infrastructure: vec![], unknown: vec![] })
    }
}

async fn get_top_blocked(State(state): State<AppState>, ConnectInfo(_addr): ConnectInfo<SocketAddr>, Query(params): Query<StatsQuery>) -> Json<Vec<DomainCount>> {
    let ip = match params.device_id {
        Some(id) if !id.trim().is_empty() => id,
        _ => "".to_string(),
    };

    let blocked_result = if ip.is_empty() {
        state.analytics.get_top_blocked().await
    } else {
        state.analytics.get_top_blocked_for_ip(&ip).await
    };

    if let Ok(domains) = blocked_result {
        Json(domains.into_iter().map(|(d, c)| DomainCount { domain: d, count: c }).collect())
    } else {
        Json(vec![])
    }
}

#[derive(Serialize)]
struct ListInfo {
    name: String,
    enabled: bool,
    rule_count: usize,
}

async fn get_lists(State(state): State<AppState>) -> Json<Vec<ListInfo>> {
    let bl = state.blocklist.read().await;
    let mut res = Vec::new();
    for l in bl.list_status() {
        res.push(ListInfo {
            name: l.name.clone(),
            enabled: l.enabled,
            rule_count: l.rule_count,
        });
    }
    Json(res)
}

#[derive(Deserialize)]
struct BlocklistCreateRequest {
    name: String,
    source_url: String,
}

async fn post_blocklist(State(state): State<AppState>, Json(req): Json<BlocklistCreateRequest>) -> Json<ActionResponse> {
    if req.name.trim().is_empty() || req.name.len()>128 || !req.source_url.starts_with("https://") {
        return Json(ActionResponse{success:false,message:"Provide a name and an HTTPS blocklist URL".into()});
    }
    let _update=blocklist::UPDATE_LOCK.lock().await;
    let mut lists=state.blocklist.read().await.get_lists();
    if lists.iter().any(|l|l.name==req.name || l.source_url==req.source_url) {
        return Json(ActionResponse{success:false,message:"Blocklist already exists".into()});
    }
    lists.push(blocklist::ListMetadata{name:req.name,source_url:req.source_url,last_updated:None,checksum:None,enabled:true,rule_count:0});
    publish_lists(&state,lists).await
}

async fn publish_lists(state:&AppState, lists:Vec<blocklist::ListMetadata>) -> Json<ActionResponse> {
    match BlocklistManager::download_lists(lists).await {
        Ok((lists,domains,exceptions))=>{state.blocklist.write().await.apply_update(lists,domains,exceptions); Json(ActionResponse{success:true,message:"Blocklist snapshot updated".into()})}
        Err(e)=>Json(ActionResponse{success:false,message:format!("Existing protection retained: {}",e)}),
    }
}

async fn delete_blocklist(State(state): State<AppState>, Path(name): Path<String>) -> Json<ActionResponse> {
    let _update=blocklist::UPDATE_LOCK.lock().await;
    let mut lists=state.blocklist.read().await.get_lists();
    let Some(list)=lists.iter_mut().find(|l|l.name==name) else {return Json(ActionResponse{success:false,message:"List not found".into()});};
    // Persist a disabled marker for local files so scanning does not silently re-add them.
    if list.source_url.starts_with("file://") {list.enabled=false;} else {lists.retain(|l|l.name!=name);}
    publish_lists(&state,lists).await
}

#[derive(Deserialize)]
struct DomainRequest {
    domain: String,
    device_id: Option<String>,
}

#[derive(Serialize)]
struct ActionResponse {
    success: bool,
    message: String,
}

async fn update_rule(state:AppState,req:DomainRequest,action:&str)->Json<ActionResponse> {
    let domain=config::canonical_domain(&req.domain);
    if !config::valid_domain(&domain) || req.device_id.as_ref().is_some_and(|ip|ip.parse::<std::net::IpAddr>().is_err()) {
        return Json(ActionResponse{success:false,message:"Invalid domain or device IP".into()});
    }
    let mut current=state.policy.write().await;
    let mut next=current.clone();
    match (action, req.device_id) {
        ("allow",Some(ip))=>next.allow_device(domain.clone(),ip), ("deny",Some(ip))=>next.deny_device(domain.clone(),ip),
        ("remove",Some(ip))=>next.remove_device(&domain,&ip), ("allow",None)=>next.allow(domain.clone()),
        ("deny",None)=>next.deny(domain.clone()), ("remove",None)=>next.remove(&domain), _=>unreachable!(),
    }
    if let Err(e)=next.save() {return Json(ActionResponse{success:false,message:format!("Rule not saved: {}",e)});}
    *current=next;
    // policy.json is the sole authority. Device rules must never be copied to the legacy global SQL table.
    Json(ActionResponse{success:true,message:format!("{} rule updated for {}",action,domain)})
}
async fn post_allow(State(s):State<AppState>,Json(r):Json<DomainRequest>)->Json<ActionResponse>{update_rule(s,r,"allow").await}
async fn post_deny(State(s):State<AppState>,Json(r):Json<DomainRequest>)->Json<ActionResponse>{update_rule(s,r,"deny").await}
async fn post_policy_remove(State(s):State<AppState>,Json(r):Json<DomainRequest>)->Json<ActionResponse>{update_rule(s,r,"remove").await}

#[derive(Serialize)]
struct PolicyRules {
    allowed: Vec<String>,
    denied: Vec<String>,
    device_allowed: std::collections::HashMap<String, Vec<String>>,
    device_denied: std::collections::HashMap<String, Vec<String>>,
}

async fn get_policy(State(state): State<AppState>) -> Json<PolicyRules> {
    let pol = state.policy.read().await;

    let mut device_allowed = std::collections::HashMap::new();
    for (k, v) in &pol.device_explicit_allow {
        let mut list: Vec<String> = v.iter().cloned().collect();
        list.sort();
        device_allowed.insert(k.clone(), list);
    }

    let mut device_denied = std::collections::HashMap::new();
    for (k, v) in &pol.device_explicit_deny {
        let mut list: Vec<String> = v.iter().cloned().collect();
        list.sort();
        device_denied.insert(k.clone(), list);
    }

    Json(PolicyRules {
        allowed: pol.get_allowed(),
        denied: pol.get_denied(),
        device_allowed,
        device_denied,
    })
}

async fn post_diagnose(State(state): State<AppState>, Json(req): Json<DomainRequest>) -> Json<DiagnosticReport> {
    let p = state.policy.read().await;
    let b = state.blocklist.read().await;
    let profile = if let Some(ip)=req.device_id.as_ref() {state.device_registry.read().await.get_profile(ip).to_string()} else {"default".into()};
    let report = DiagnosticEngine::diagnose_for_device(&req.domain, req.device_id.as_deref(), &profile, &p, &b);
    Json(report)
}

async fn get_devices(State(state): State<AppState>) -> Json<Vec<crate::device_registry::RegisteredDevice>> {
    let mut devices = state.device_registry.read().await.list_devices().to_vec();

    // Inject Tailscale online peers dynamically
    let ts_peers = crate::tailscale::get_online_peers().await;
    for (ip, hostname) in ts_peers {
        if !devices.iter().any(|d| d.ip == ip) {
            devices.push(crate::device_registry::RegisteredDevice {
                ip,
                name: format!("{} (Tailscale)", hostname),
                profile: "default".to_string(),
            });
        }
    }

    Json(devices)
}



use axum::response::Html;

async fn get_blocked_page(headers: axum::http::HeaderMap, Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let host_header = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("Unknown");
    let host_header = host_header.split(':').next().unwrap_or("Unknown").to_string();
    let domain = params.get("domain").cloned().unwrap_or(host_header);
    let reason = params.get("reason").cloned().unwrap_or_else(|| "Blocked by Policy".to_string());
    let source = params.get("source").cloned().unwrap_or_else(|| "AegisDNS".to_string());

    let domain = config::html_escape(&domain);
    let reason = config::html_escape(&reason);
    let source = config::html_escape(&source);
    let html = format!(r#"
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Protected by AegisDNS</title>
  <link rel="icon" type="image/png" href="/logo.png">
  <style>
    :root {{
      --bg: #ffffff;
      --surface: #f9fafb;
      --border: #e5e7eb;
      --text: #111827;
      --text-muted: #6b7280;
      --accent: #dc2626;
      --accent-hover: #b91c1c;
      --accent-light: #fef2f2;
    }}
    @media (prefers-color-scheme: dark) {{
      :root {{
        --bg: #030712;
        --surface: #111827;
        --border: #374151;
        --text: #f9fafb;
        --text-muted: #9ca3af;
        --accent: #ef4444;
        --accent-hover: #dc2626;
        --accent-light: #451a1a;
      }}
    }}
    body {{
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background-color: var(--bg);
      color: var(--text);
      display: flex;
      align-items: center;
      justify-content: center;
      height: 100vh;
      margin: 0;
      padding: 20px;
      box-sizing: border-box;
    }}
    .main-content {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 40px;
      max-width: 480px;
      width: 100%;
      box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1), 0 8px 10px -6px rgba(0, 0, 0, 0.1);
      text-align: center;
    }}
    .shield-icon {{
      height: 64px;
      width: auto;
      max-width: 100%;
      object-fit: contain;
      margin: 0 auto 24px;
      display: block;
    }}
    h1 {{
      margin: 0 0 12px;
      font-size: 24px;
      font-weight: 700;
      letter-spacing: -0.02em;
    }}
    p {{
      margin: 0 0 24px;
      color: var(--text-muted);
      font-size: 15px;
      line-height: 1.5;
    }}
    .details-box {{
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 16px;
      text-align: left;
      margin-bottom: 24px;
    }}
    .detail-row {{
      display: flex;
      justify-content: space-between;
      margin-bottom: 8px;
      font-size: 14px;
    }}
    .detail-row:last-child {{
      margin-bottom: 0;
    }}
    .detail-label {{
      color: var(--text-muted);
      font-weight: 500;
    }}
    .detail-value {{
      font-weight: 600;
      word-break: break-all;
      max-width: 65%;
      text-align: right;
    }}
    .btn {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      background: var(--text);
      color: var(--bg);
      border: none;
      border-radius: 8px;
      padding: 12px 24px;
      font-size: 15px;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.2s;
      text-decoration: none;
      width: 100%;
      box-sizing: border-box;
    }}
    .btn:hover {{
      opacity: 0.9;
    }}
    .footer {{
      margin-top: 32px;
      text-align: center;
    }}
    .footer-brand {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--text-muted);
      font-size: 13px;
      font-weight: 600;
    }}
    .footer-brand img {{
      height: 16px;
      width: auto;
      object-fit: contain;
    }}
  </style>
</head>
<body>
  <div class="main-content">
    <img src="/logo.png" class="shield-icon" alt="AegisDNS Logo" />
    <h1>Access Blocked</h1>
    <p>This connection was terminated by AegisDNS to protect your network.</p>

    <div class="details-box">
      <div class="detail-row">
        <span class="detail-label">Domain</span>
        <span class="detail-value" style="font-family: monospace;">{domain}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Reason</span>
        <span class="detail-value">{reason}</span>
      </div>
      <div class="detail-row">
        <span class="detail-label">Source</span>
        <span class="detail-value" style="color: var(--accent);">{source}</span>
      </div>
    </div>

    <div class="actions-container" style="display: flex; gap: 12px;">
      <button class="btn" type="button" disabled title="Use your browser Back button">
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="19" y1="12" x2="5" y2="12"></line><polyline points="12 19 5 12 12 5"></polyline></svg>
        Back
      </button>
    </div>
  </div>

  <div class="footer" style="position: absolute; bottom: 24px; width: 100%; text-align: center; left: 0;">
    <div class="footer-brand">
      <img src="/logo.png" alt="AegisDNS" />
      Protected by AegisDNS
    </div>
  </div>
</body>
</html>
    "#);

    Html(html)
}

async fn get_logo() -> (axum::http::StatusCode, axum::http::HeaderMap, &'static [u8]) {
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(axum::http::header::CONTENT_TYPE, "image/png".parse().unwrap());
    headers.insert(axum::http::header::CACHE_CONTROL, "public, max-age=31536000".parse().unwrap());

    let logo_bytes = include_bytes!("../../../assets/logo.png");
    (axum::http::StatusCode::OK, headers, logo_bytes)
}

// ============================================================
// Schedule Handlers
// ============================================================

#[derive(Deserialize)]
struct CreateScheduleRequest {
    domain: String,
    action: String,       // "block" or "allow"
    days: Vec<u8>,        // 0=Sun..6=Sat
    start_hour: u8,
    start_min: u8,
    end_hour: u8,
    end_min: u8,
    device_id: Option<String>,
    label: String,
}

async fn get_schedules(State(state): State<AppState>) -> Json<Vec<ScheduleRule>> {
    let pol = state.policy.read().await;
    Json(pol.schedules.clone())
}

async fn post_schedule(State(state): State<AppState>, Json(req): Json<CreateScheduleRequest>) -> Json<ActionResponse> {
    if !matches!(req.action.as_str(),"allow"|"block") || req.days.is_empty() || req.days.iter().any(|d|*d>6) || req.start_hour>23 || req.end_hour>23 || req.start_min>59 || req.end_min>59 || !config::valid_domain(&config::canonical_domain(&req.domain)) || req.label.len()>256 || req.device_id.as_ref().is_some_and(|ip|ip.parse::<std::net::IpAddr>().is_err()) {
        return Json(ActionResponse{success:false,message:"Invalid schedule parameters".into()});
    }
    let action = if req.action == "allow" { ScheduleAction::Allow } else { ScheduleAction::Block };
    let rule = ScheduleRule {
        id: format!("{:x}", std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()),
        domain: req.domain.clone(),
        action,
        days: req.days,
        start_minutes: req.start_hour as u16 * 60 + req.start_min as u16,
        end_minutes: req.end_hour as u16 * 60 + req.end_min as u16,
        device_id: req.device_id,
        enabled: true,
        label: req.label.clone(),
    };
    let id = rule.id.clone();
    {
        let mut pol = state.policy.write().await;
        let mut next=pol.clone(); next.add_schedule(rule);
        if let Err(e)=next.save() { return Json(ActionResponse{success:false,message:e.to_string()}); }
        *pol=next;
    }
    Json(ActionResponse { success: true, message: format!("Schedule '{}' created (id: {})", req.label, id) })
}

async fn delete_schedule(State(state): State<AppState>, Path(id): Path<String>) -> Json<ActionResponse> {
    let mut pol = state.policy.write().await;
    let mut next=pol.clone(); next.remove_schedule(&id);
    if let Err(e)=next.save() {return Json(ActionResponse{success:false,message:e.to_string()});}
    *pol=next;
    Json(ActionResponse { success: true, message: format!("Schedule {} removed", id) })
}

#[derive(Deserialize)]
struct ToggleRequest { enabled: bool }

async fn put_schedule_toggle(State(state): State<AppState>, Path(id): Path<String>, Json(req): Json<ToggleRequest>) -> Json<ActionResponse> {
    let mut pol = state.policy.write().await;
    let mut next=pol.clone(); next.toggle_schedule(&id, req.enabled);
    if let Err(e)=next.save() {return Json(ActionResponse{success:false,message:e.to_string()});}
    *pol=next;
    Json(ActionResponse { success: true, message: format!("Schedule {} {}", id, if req.enabled { "enabled" } else { "disabled" }) })
}

// ============================================================
// Risk Scoring Handler
// ============================================================

#[derive(Deserialize)]
struct RiskRequest { domain: String }

async fn post_risk(_state: State<AppState>, Json(req): Json<RiskRequest>) -> Result<Json<risk::RiskScore>,axum::http::StatusCode> {
    let domain=config::canonical_domain(&req.domain);
    if !config::valid_domain(&domain) {return Err(axum::http::StatusCode::BAD_REQUEST);}
    Ok(Json(score_domain(&domain)))
}

// ============================================================
// Safe Search Handlers
// ============================================================

#[derive(Serialize)]
struct SafeSearchStatus { enabled: bool }

#[derive(Deserialize)]
struct SafeSearchToggle { enabled: bool }

async fn get_safesearch(State(state): State<AppState>) -> Json<SafeSearchStatus> {
    let pol = state.policy.read().await;
    Json(SafeSearchStatus { enabled: pol.safe_search_enabled })
}

async fn post_safesearch(State(state): State<AppState>, Json(req): Json<SafeSearchToggle>) -> Json<ActionResponse> {
    let mut pol = state.policy.write().await;
    let mut next=pol.clone(); next.safe_search_enabled=req.enabled;
    if let Err(e)=next.save() {return Json(ActionResponse{success:false,message:e.to_string()});}
    *pol=next;
    Json(ActionResponse {
        success: true,
        message: format!("Safe search {}", if req.enabled { "enabled" } else { "disabled" }),
    })
}

// ============================================================

async fn get_quarantine(State(s): State<AppState>) -> Json<Vec<String>> {
    let q = s.anomaly.quarantined.read().await;
    Json(q.iter().cloned().collect())
}

async fn delete_quarantine(State(s): State<AppState>, Path(ip): Path<String>) -> axum::http::StatusCode {
    s.anomaly.unquarantine(&ip).await;
    axum::http::StatusCode::OK
}

#[derive(Deserialize)]
struct DeleteLogsRequest {
    timeframe: String,
}

async fn delete_logs(State(state): State<AppState>, Json(req): Json<DeleteLogsRequest>) -> Json<ActionResponse> {
    match state.analytics.delete_logs(&req.timeframe).await {
        Ok(_) => Json(ActionResponse {
            success: true,
            message: "Logs deleted successfully".into(),
        }),
        Err(e) => Json(ActionResponse {
            success: false,
            message: format!("Failed to delete logs: {}", e),
        }),
    }
}

// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•
// Custom DNS Actions Engine  â€” REST API handlers
// â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•â•

#[derive(Deserialize)]
struct CreateActionRequest {
    domain:        String,
    action_type:   String,
    payload_url:   Option<String>,
    method:        Option<String>,
    shell_command: Option<String>,
    html_content:  Option<String>,
    success_msg:   Option<String>,
    token:         Option<String>,
}

async fn get_actions(State(state): State<AppState>) -> Json<Vec<analytics::CustomAction>> {
    Json(state.analytics.list_actions().unwrap_or_default())
}

async fn post_action(
    State(state): State<AppState>,
    Json(req): Json<CreateActionRequest>,
) -> Json<ActionResponse> {
    let domain = config::canonical_domain(&req.domain);
    if !config::valid_domain(&domain) || !config::dns::local_zone(&domain) {
        return Json(ActionResponse { success:false, message:"Actions require a valid local domain (.root, .aegis, .lan or .home.arpa)".into() });
    }
    if let Err(e) = crate::actions::validate(&req.action_type, req.shell_command.as_deref(), req.payload_url.as_deref(), req.method.as_deref(), req.token.as_deref()) {
        return Json(ActionResponse { success:false, message:e.to_string() });
    }
    match state.analytics.upsert_action(
        &domain,
        &req.action_type,
        req.payload_url.as_deref(),
        req.method.as_deref(),
        req.shell_command.as_deref(),
        req.html_content.as_deref(),
        req.success_msg.as_deref(),
        req.token.as_deref(),
    ) {
        Ok(_) => {
            crate::actions::invalidate(&domain);
            Json(ActionResponse { success: true, message: format!("Action for '{}' saved.", domain) })
        }
        Err(e) => Json(ActionResponse { success: false, message: e.to_string() }),
    }
}

async fn delete_action(
    State(state): State<AppState>,
    Path(domain): Path<String>,
) -> Json<ActionResponse> {
    let domain = domain.trim().to_lowercase();
    match state.analytics.delete_action(&domain) {
        Ok(_) => {
            crate::actions::invalidate(&domain);
            Json(ActionResponse { success: true, message: format!("Action for '{}' deleted.", domain) })
        }
        Err(e) => Json(ActionResponse { success: false, message: e.to_string() }),
    }
}

#[derive(Deserialize)]
struct ActionLogsQuery {
    domain: Option<String>,
    limit:  Option<u32>,
}

async fn get_action_logs(
    State(state): State<AppState>,
    Query(q): Query<ActionLogsQuery>,
) -> Json<Vec<analytics::ActionLog>> {
    let limit = q.limit.unwrap_or(50).min(200);
    Json(state.analytics.get_action_logs(q.domain.as_deref(), limit).unwrap_or_default())
}

async fn clear_action_logs(
    State(state): State<AppState>,
) -> Json<ActionResponse> {
    match state.analytics.clear_action_logs() {
        Ok(_) => Json(ActionResponse { success: true, message: "Logs cleared".into() }),
        Err(e) => Json(ActionResponse { success: false, message: e.to_string() }),
    }
}

#[derive(serde::Deserialize)]
pub struct ClassifyRequest {
    pub domain: String,
    pub category: String, // "destination", "infrastructure", "unknown"
}

pub async fn set_classification(axum::extract::State(state): axum::extract::State<AppState>, axum::extract::Json(payload): axum::extract::Json<ClassifyRequest>) -> Result<axum::extract::Json<()>, axum::http::StatusCode> {
    if payload.category == "unknown" {
        let _ = state.analytics.set_classification(&payload.domain, "unknown").await;
    } else {
        let _ = state.analytics.set_classification(&payload.domain, &payload.category).await;
    }
    Ok(axum::extract::Json(()))
}

async fn get_recent(axum::extract::State(state): axum::extract::State<AppState>, axum::extract::Query(params): axum::extract::Query<StatsQuery>) -> axum::Json<Vec<analytics::RecentQuery>> {
    let ip = params.device_id.filter(|s| !s.trim().is_empty());
    axum::Json(state.analytics.get_recent_queries(50, ip.as_deref()).unwrap_or_default())
}

pub async fn live_feed_stream(axum::extract::State(state): axum::extract::State<AppState>) -> axum::response::sse::Sse<impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>> {
    let rx = state.analytics.live_tx.subscribe();

    let stream = futures_util::stream::unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(event) => {
                    if let Ok(json) = serde_json::to_string(&event) {
                        return Some((Ok(axum::response::sse::Event::default().data(json)), rx));
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    axum::response::sse::Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(std::time::Duration::from_secs(15))
            .text("keep-alive-text"),
    )
}

#[derive(serde::Deserialize)]
pub struct FaviconQuery {
    domain: String,
}

pub async fn get_favicon(axum::extract::Query(params): axum::extract::Query<FaviconQuery>) -> axum::response::Response {
    let _ = params.domain;
    axum::response::Response::builder()
        .header("Content-Type", "image/svg+xml")
        .header("Cache-Control", "public, max-age=86400")
        .body(axum::body::Body::from(r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><circle cx="12" cy="12" r="10" fill="none" stroke="#888"/><path d="M2 12h20M12 2v20" stroke="#888"/></svg>"##)).unwrap()
}

// ============================================================
// Device Management Handlers (POST add, DELETE remove, PUT profile)
// ============================================================

#[derive(Deserialize)]
struct AddDeviceRequest {
    ip:   String,
    name: String,
}

async fn post_device(State(state): State<AppState>, Json(req): Json<AddDeviceRequest>) -> Json<ActionResponse> {
    let mut reg = state.device_registry.write().await;
    match reg.add_device(req.ip.clone(), req.name.clone()) {
        Ok(_) => Json(ActionResponse { success: true, message: format!("Device {} ({}) added", req.name, req.ip) }),
        Err(e) => Json(ActionResponse { success: false, message: e }),
    }
}

async fn delete_device(State(state): State<AppState>, Path(ip): Path<String>) -> Json<ActionResponse> {
    let mut reg = state.device_registry.write().await;
    match reg.remove_device(&ip) {
        Ok(_) => Json(ActionResponse { success: true, message: format!("Device {} removed", ip) }),
        Err(e) => Json(ActionResponse { success: false, message: e }),
    }
}

#[derive(Deserialize)]
struct SetProfileRequest { profile: String }

async fn put_device_profile(State(state): State<AppState>, Path(ip): Path<String>, Json(req): Json<SetProfileRequest>) -> Json<ActionResponse> {
    let mut reg = state.device_registry.write().await;
    match reg.set_profile(&ip, &req.profile) {
        Ok(_) => Json(ActionResponse { success: true, message: format!("Profile for {} set to {}", ip, req.profile) }),
        Err(e) => Json(ActionResponse { success: false, message: e }),
    }
}

// ============================================================
// Telegram Config Handlers (GET config, POST save, POST test)
// ============================================================

/// Shape returned to / accepted from the frontend.
/// Uses `notify_on_block` to match the JS field name.
#[derive(Serialize, Deserialize)]
struct TelegramConfigWeb {
    enabled:          bool,
    bot_token:        String,
    #[serde(default)]
    bot_token_configured: bool,
    chat_id:          String,
    threat_threshold: u8,
    notify_on_block:  bool,
}

async fn get_telegram(State(state): State<AppState>) -> Json<TelegramConfigWeb> {
    let cfg = state.telegram_cfg.read().await;
    Json(TelegramConfigWeb {
        enabled:          cfg.enabled,
        bot_token:        String::new(),
        bot_token_configured: !cfg.bot_token.is_empty(),
        chat_id:          cfg.chat_id.clone(),
        threat_threshold: cfg.threat_threshold,
        notify_on_block:  cfg.notify_blocked,
    })
}

async fn post_telegram(State(state): State<AppState>, Json(req): Json<TelegramConfigWeb>) -> Json<ActionResponse> {
    let existing_token = state.telegram_cfg.read().await.bot_token.clone();
    let bot_token = if req.bot_token.is_empty() { existing_token } else { req.bot_token.clone() };
    let valid_token = bot_token.is_empty()
        || (bot_token.len() >= 32 && bot_token.len() <= 256 && bot_token.contains(':') && !bot_token.chars().any(char::is_control));
    let valid_chat = req.chat_id.is_empty()
        || (req.chat_id.len() <= 64 && req.chat_id.trim_start_matches('-').chars().all(|c| c.is_ascii_digit()));
    if !valid_token || !valid_chat || !(1..=100).contains(&req.threat_threshold)
        || (req.enabled && (bot_token.is_empty() || req.chat_id.is_empty())) {
        return Json(ActionResponse { success: false, message: "Invalid Telegram token, chat ID, or threshold".into() });
    }
    let new_cfg = crate::telegram::TelegramConfig {
        enabled:          req.enabled,
        bot_token,
        chat_id:          req.chat_id.clone(),
        threat_threshold: req.threat_threshold,
        notify_blocked:   req.notify_on_block,
    };
    // Persist to disk
    match crate::telegram::save_config(&new_cfg) {
        Ok(_) => {},
        Err(e) => return Json(ActionResponse { success: false, message: format!("Failed to save: {}", e) }),
    }
    // Update in-memory state
    *state.telegram_cfg.write().await = new_cfg;
    Json(ActionResponse { success: true, message: "Telegram configuration saved".into() })
}

async fn post_telegram_test(State(state): State<AppState>) -> Json<ActionResponse> {
    let cfg = state.telegram_cfg.read().await.clone();
    if !cfg.enabled || cfg.bot_token.is_empty() || cfg.chat_id.is_empty() {
        return Json(ActionResponse {
            success: false,
            message: "Telegram is not configured or not enabled. Save your config first.".into(),
        });
    }
    match crate::telegram::send_message(
        &cfg,
        "🛡️ <b>AegisDNS Test Message</b>\n\nYour Telegram integration is working correctly!",
    ).await {
        Ok(()) => Json(ActionResponse { success: true, message: "Test message sent".into() }),
        Err(e) => Json(ActionResponse { success: false, message: e }),
    }
}

// ============================================================
// DHCP Server Settings Handler
// ============================================================

async fn get_dhcp() -> Json<crate::dhcp::DhcpConfig> {
    Json(crate::dhcp::load_config())
}

async fn post_dhcp(Json(cfg): Json<crate::dhcp::DhcpConfig>) -> Json<ActionResponse> {
    match crate::dhcp::save_config(&cfg) {
        Ok(_) => Json(ActionResponse { success: true, message: "DHCP configuration saved. Restart server to apply!".into() }),
        Err(e) => Json(ActionResponse { success: false, message: format!("Failed to save: {}", e) }),
    }
}

// ============================================================
// Log Export Handler (GET /api/export/logs?days=&status=&ip=&format=)
// ============================================================

#[derive(Deserialize)]
struct ExportQuery {
    days:   Option<u32>,
    status: Option<String>,
    ip:     Option<String>,
    format: Option<String>,
}

async fn get_export_logs(State(state): State<AppState>, Query(q): Query<ExportQuery>) -> axum::response::Response {
    let days   = q.days.unwrap_or(7).min(90);
    let status = q.status.as_deref().filter(|s| !s.is_empty() && *s != "all");
    let ip     = q.ip.as_deref().filter(|s| !s.is_empty() && *s != "all");
    let fmt    = q.format.as_deref().unwrap_or("csv");

    let rows = match state.analytics.get_queries_for_export(status, ip, days) {
        Ok(r)  => r,
        Err(e) => {
            return axum::response::Response::builder()
                .status(500)
                .body(axum::body::Body::from(format!("Export failed: {}", e)))
                .unwrap();
        }
    };

    if fmt == "json" {
        let json = serde_json::to_string(&rows).unwrap_or_default();
        return axum::response::Response::builder()
            .header("Content-Type", "application/json")
            .header("Content-Disposition", "attachment; filename=\"aegisdns_logs.json\"")
            .body(axum::body::Body::from(json))
            .unwrap();
    }

    // Default: CSV
    let mut csv = String::from("timestamp,domain,status,client_ip\n");
    for r in &rows {
        csv.push_str(&format!(
            "{},{},{},{}\n",
            csv_cell(&r.timestamp), csv_cell(&r.domain), csv_cell(&r.status), csv_cell(&r.client_ip)
        ));
    }
    axum::response::Response::builder()
        .header("Content-Type", "text/csv")
        .header("Content-Disposition", "attachment; filename=\"aegisdns_logs.csv\"")
        .body(axum::body::Body::from(csv))
        .unwrap()
}

// ============================================================
// Restart Handler — exits cleanly; Docker restart policy revives
// ============================================================

async fn post_restart(State(state): State<AppState>) -> Json<ActionResponse> {
    tracing::info!("Restart requested via API");
    let restart=state.restart.clone();
    // Let Axum write the response before main begins graceful shutdown.
    tokio::spawn(async move {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        restart.notify_one();
    });
    Json(ActionResponse { success: true, message: "Restarting AegisDNS…".into() })
}

// ============================================================
// Telegram Chat-ID Auto-Detect Proxy
// (Browser can't call api.telegram.org directly due to CORS)
// ============================================================

#[derive(Deserialize)]
struct DetectRequest { token: String }

async fn post_telegram_detect(Json(q): Json<DetectRequest>) -> axum::response::Response {
    if q.token.len() < 32 || q.token.len() > 256 || !q.token.contains(':') || q.token.chars().any(char::is_control) {
        return axum::response::Response::builder()
            .status(400)
            .header("Content-Type", "application/json")
            .body(axum::body::Body::from(r#"{"ok":false,"description":"token is required"}"#))
            .unwrap();
    }
    match crate::telegram::proxy_get_updates(&q.token).await {
        Ok(json) => {
            let body = serde_json::to_string(&json).unwrap_or_default();
            axum::response::Response::builder()
                .status(200)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap()
        }
        Err(e) => {
            let body = serde_json::to_string(&serde_json::json!({
                "ok": false,
                "description": e
            })).unwrap_or_default();
            axum::response::Response::builder()
                .status(502)
                .header("Content-Type", "application/json")
                .body(axum::body::Body::from(body))
                .unwrap()
        }
    }
}

async fn get_upstream(State(s): State<AppState>) -> Json<crate::upstream::UpstreamDnsConfig> {
    let cfg = s.upstream_cfg.read().await.clone();
    Json(cfg)
}

async fn post_upstream(
    State(s): State<AppState>,
    Json(payload): Json<crate::upstream::UpstreamDnsConfig>,
) -> Json<serde_json::Value> {
    if let Err(e) = crate::upstream::save_config(&payload).await {
        return Json(serde_json::json!({"success":false,"message":e.to_string()}));
    }
    *s.upstream_cfg.write().await = payload;
    Json(serde_json::json!({"success":true,"message":"Saved. Validating resolver will restart within two seconds."}))
}

fn csv_cell(value:&str)->String {
    let value=if value.starts_with(['=','+','-','@','\t','\r']) {format!("'{}",value)} else {value.to_string()};
    format!("\"{}\"",value.replace('"',"\"\""))
}
#[cfg(test)] mod security_tests {
    use super::*;
    #[tokio::test] async fn block_page_escapes_all_parameters() {
        let marker="<script>alert(1)</script>";
        let params=HashMap::from([("domain".into(),marker.into()),("reason".into(),marker.into()),("source".into(),marker.into())]);
        let Html(body)=get_blocked_page(Default::default(),Query(params)).await;
        assert!(!body.contains(marker)); assert!(body.contains("&lt;script&gt;"));
    }
    #[test] fn csv_quotes_formula_and_delimiters() { assert_eq!(csv_cell("=1+1"),"\"'=1+1\""); assert_eq!(csv_cell("a,b"),"\"a,b\""); }
}
