use axum::{
    routing::{get, post, delete, put},
    Router,
    Json,
    extract::{State, ConnectInfo, Query, Path},
};
use std::net::SocketAddr;
use tower_http::services::ServeDir;
use tower_http::cors::CorsLayer;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use analytics::AnalyticsDb;
use policy::{PolicyEngine, ScheduleRule, ScheduleAction};
use blocklist::BlocklistManager;
use fallback::{FallbackEngine, FallbackMode};
use diagnostics::{DiagnosticEngine, DiagnosticReport};
use risk::score_domain;
use std::collections::HashMap;

#[derive(Clone)]
#[allow(dead_code)]
struct AppState {
    analytics: Arc<AnalyticsDb>,
    policy: Arc<RwLock<PolicyEngine>>,
    blocklist: Arc<RwLock<BlocklistManager>>,
    fallback: Arc<RwLock<FallbackEngine>>,
}

pub async fn start_web_server(
    analytics: Arc<AnalyticsDb>,
    policy: Arc<RwLock<PolicyEngine>>,
    blocklist: Arc<RwLock<BlocklistManager>>,
    fallback: Arc<RwLock<FallbackEngine>>,
) -> anyhow::Result<()> {
    let state = AppState {
        analytics,
        policy,
        blocklist,
        fallback,
    };

    let app = Router::new()
        .route("/api/stats", get(get_stats))
        .route("/api/top-domains", get(get_top_domains))
        .route("/api/top-blocked", get(get_top_blocked))
        .route("/api/lists", get(get_lists))
        .route("/api/allow", post(post_allow))
        .route("/api/deny", post(post_deny))
        .route("/api/fallback", post(post_fallback))
        .route("/api/diagnose", post(post_diagnose))
        .route("/api/policy", get(get_policy))
        .route("/api/policy/remove", post(post_policy_remove))
        .route("/api/devices", get(get_devices))
        .route("/api/schedules", get(get_schedules))
        .route("/api/schedules", post(post_schedule))
        .route("/api/schedules/:id", delete(delete_schedule))
        .route("/api/schedules/:id/toggle", put(put_schedule_toggle))
        .route("/api/risk", post(post_risk))
        .route("/api/safesearch", get(get_safesearch))
        .route("/api/safesearch", post(post_safesearch))
        .route("/api/me", get(get_my_ip))
        .route("/api/threats", get(get_threat_status))
        .route("/blocked", get(get_blocked_page))
        .route("/logo.png", get(get_logo))
        .fallback_service(ServeDir::new("/usr/share/aegisdns/ui"))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:5380").await?;
    tracing::info!("Web UI server listening on http://127.0.0.1:5380");
    axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await?;

    Ok(())
}

#[derive(Serialize)]
struct MyIp { ip: String }

async fn get_my_ip(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> Json<MyIp> {
    let ip = normalize_ip(&addr.ip().to_string());
    Json(MyIp { ip })
}

pub async fn start_block_page_server(
    policy: Arc<RwLock<policy::PolicyEngine>>,
    blocklist: Arc<RwLock<blocklist::BlocklistManager>>,
) -> anyhow::Result<()> {
    use axum::{extract::Host, routing::get, response::Html};
    
    let app = Router::new()
        .route("/logo.png", get(get_logo))
        .fallback(get(move |Host(host): Host| {
            let policy = policy.clone();
            let blocklist = blocklist.clone();
            async move {
                let pol = policy.read().await;
                let bl = blocklist.read().await;
                let diag = diagnostics::DiagnosticEngine::diagnose(&host, &pol, &bl);
                
                Html(format!(
                    r##"<!DOCTYPE html>
                    <html><head><title>Blocked by AegisDNS</title>
                    <style>
                    body {{ font-family: -apple-system, system-ui, sans-serif; background: #0f0f14; color: #e2e8f0; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
                    .container {{ background: #1e1e2e; padding: 40px 50px; border-radius: 16px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); max-width: 500px; text-align: center; border: 1px solid #333; }}
                    h1 {{ color: #f7768e; font-size: 24px; margin-bottom: 10px; }}
                    .domain {{ font-size: 20px; font-weight: bold; color: #7aa2f7; margin: 20px 0; background: #292e42; padding: 10px; border-radius: 8px; }}
                    .info {{ text-align: left; background: #15161e; padding: 15px; border-radius: 8px; margin-bottom: 25px; }}
                    .info p {{ margin: 8px 0; font-size: 14px; color: #a9b1d6; }}
                    strong {{ color: #c0caf5; }}
                    </style>
                    </head>
                    <body>
                    <div class="container">
                        <svg width="64" height="64" viewBox="0 0 24 24" fill="none" stroke="#f7768e" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path><line x1="9" y1="9" x2="15" y2="15"></line><line x1="15" y1="9" x2="9" y2="15"></line></svg>
                        <h1>Access Blocked</h1>
                        <p>This connection was terminated by AegisDNS to protect your network.</p>
                        <div class="domain">{}</div>
                        <div class="info">
                            <p><strong>Reason:</strong> {}</p>
                            <p><strong>Source:</strong> {}</p>
                        </div>
                        <p style="font-size: 13px; color: #565f89; margin-bottom: 20px;">If you believe this is a mistake, you can allow this domain via the AegisDNS Browser Extension.</p>
                    </div>
                    </body></html>"##,
                    host, diag.reason, diag.source
                ))
            }
        }));
    
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 80));
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Block page server listening on http://0.0.0.0:80");
    axum::serve(listener, app).await?;
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

async fn get_stats(State(state): State<AppState>, ConnectInfo(addr): ConnectInfo<SocketAddr>, Query(params): Query<StatsQuery>) -> Json<WebStats> {
    let ip = if let Some(id) = params.device_id {
        id
    } else {
        normalize_ip(&addr.ip().to_string())
    };
    if let Ok(stats) = state.analytics.get_stats_for_ip(&ip).await {
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
struct DomainCount {
    domain: String,
    count: u64,
}

async fn get_top_domains(State(state): State<AppState>, ConnectInfo(addr): ConnectInfo<SocketAddr>, Query(params): Query<StatsQuery>) -> Json<Vec<DomainCount>> {
    let ip = if let Some(id) = params.device_id {
        id
    } else {
        normalize_ip(&addr.ip().to_string())
    };
    if let Ok(domains) = state.analytics.get_top_domains_for_ip(&ip).await {
        Json(domains.into_iter().map(|(d, c)| DomainCount { domain: d, count: c }).collect())
    } else {
        Json(vec![])
    }
}

async fn get_top_blocked(State(state): State<AppState>, ConnectInfo(addr): ConnectInfo<SocketAddr>, Query(params): Query<StatsQuery>) -> Json<Vec<DomainCount>> {
    let ip = if let Some(id) = params.device_id {
        id
    } else {
        normalize_ip(&addr.ip().to_string())
    };
    if let Ok(domains) = state.analytics.get_top_blocked_for_ip(&ip).await {
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
struct DomainRequest {
    domain: String,
    device_id: Option<String>,
}

#[derive(Serialize)]
struct ActionResponse {
    success: bool,
    message: String,
}

async fn post_allow(State(state): State<AppState>, Json(req): Json<DomainRequest>) -> Json<ActionResponse> {
    let domain = if req.domain.starts_with("www.") { req.domain[4..].to_string() } else { req.domain.clone() };
    {
        let mut p = state.policy.write().await;
        if let Some(did) = req.device_id {
            p.allow_device(domain.clone(), did);
        } else {
            p.allow(domain.clone());
        }
        let _ = p.save();
    }
    let _ = state.analytics.set_policy_rule(&domain, "allow");
    Json(ActionResponse {
        success: true,
        message: format!("Allowed {}", domain),
    })
}

async fn post_deny(State(state): State<AppState>, Json(req): Json<DomainRequest>) -> Json<ActionResponse> {
    let domain = if req.domain.starts_with("www.") { req.domain[4..].to_string() } else { req.domain.clone() };
    {
        let mut p = state.policy.write().await;
        if let Some(did) = req.device_id {
            p.deny_device(domain.clone(), did);
        } else {
            p.deny(domain.clone());
        }
        let _ = p.save();
    }
    let _ = state.analytics.set_policy_rule(&domain, "deny");
    Json(ActionResponse {
        success: true,
        message: format!("Blocked {}", domain),
    })
}

async fn post_policy_remove(State(state): State<AppState>, Json(req): Json<DomainRequest>) -> Json<ActionResponse> {
    let domain = if req.domain.starts_with("www.") { req.domain[4..].to_string() } else { req.domain.clone() };
    {
        let mut p = state.policy.write().await;
        if let Some(did) = req.device_id {
            p.remove_device(&domain, &did);
        } else {
            p.remove(&domain);
        }
        let _ = p.save();
    }
    let _ = state.analytics.remove_policy_rule(&domain);
    Json(ActionResponse {
        success: true,
        message: format!("Removed rule for {}", domain),
    })
}

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

async fn post_fallback(State(state): State<AppState>, Json(req): Json<DomainRequest>) -> Json<ActionResponse> {
    state.fallback.write().await.add_fallback(req.domain.clone(), FallbackMode::Permanent);
    Json(ActionResponse {
        success: true,
        message: format!("Fallback enabled for {}", req.domain),
    })
}

async fn post_diagnose(State(state): State<AppState>, Json(req): Json<DomainRequest>) -> Json<DiagnosticReport> {
    let p = state.policy.read().await;
    let b = state.blocklist.read().await;
    let report = DiagnosticEngine::diagnose(&req.domain, &p, &b);
    Json(report)
}

async fn get_devices(State(state): State<AppState>) -> Json<Vec<String>> {
    let devices = state.analytics.get_connected_devices().await.unwrap_or_default();
    Json(devices)
}



use axum::response::Html;

async fn get_blocked_page(headers: axum::http::HeaderMap, Query(params): Query<HashMap<String, String>>) -> Html<String> {
    let host_header = headers.get("host").and_then(|h| h.to_str().ok()).unwrap_or("Unknown");
    let host_header = host_header.split(':').next().unwrap_or("Unknown").to_string();
    let domain = params.get("domain").cloned().unwrap_or(host_header);
    let reason = params.get("reason").cloned().unwrap_or_else(|| "Blocked by Policy".to_string());
    let source = params.get("source").cloned().unwrap_or_else(|| "AegisDNS".to_string());

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
      <button class="btn" onclick="window.history.back()">
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
        pol.add_schedule(rule);
        let _ = pol.save();
    }
    Json(ActionResponse { success: true, message: format!("Schedule '{}' created (id: {})", req.label, id) })
}

async fn delete_schedule(State(state): State<AppState>, Path(id): Path<String>) -> Json<ActionResponse> {
    let mut pol = state.policy.write().await;
    pol.remove_schedule(&id);
    let _ = pol.save();
    Json(ActionResponse { success: true, message: format!("Schedule {} removed", id) })
}

#[derive(Deserialize)]
struct ToggleRequest { enabled: bool }

async fn put_schedule_toggle(State(state): State<AppState>, Path(id): Path<String>, Json(req): Json<ToggleRequest>) -> Json<ActionResponse> {
    let mut pol = state.policy.write().await;
    pol.toggle_schedule(&id, req.enabled);
    let _ = pol.save();
    Json(ActionResponse { success: true, message: format!("Schedule {} {}", id, if req.enabled { "enabled" } else { "disabled" }) })
}

// ============================================================
// Risk Scoring Handler
// ============================================================

#[derive(Deserialize)]
struct RiskRequest { domain: String }

async fn post_risk(_state: State<AppState>, Json(req): Json<RiskRequest>) -> Json<risk::RiskScore> {
    Json(score_domain(&req.domain))
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
    pol.safe_search_enabled = req.enabled;
    let _ = pol.save();
    Json(ActionResponse {
        success: true,
        message: format!("Safe search {}", if req.enabled { "enabled" } else { "disabled" }),
    })
}

// ============================================================
// Threat Feed Status Handler
// ============================================================

#[derive(Serialize)]
struct ThreatStatus {
    live_threat_count: usize,
    last_updated: Option<String>,
}

async fn get_threat_status(State(state): State<AppState>) -> Json<ThreatStatus> {
    let bl = state.blocklist.read().await;
    let last_updated = bl.realtime_last_updated.map(|t| {
        t.duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string()
    });
    Json(ThreatStatus {
        live_threat_count: bl.realtime_threat_count,
        last_updated,
    })
}



