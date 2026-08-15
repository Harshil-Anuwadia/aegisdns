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
use moka::future::Cache;
use std::time::Instant;

#[derive(Clone)]
#[allow(dead_code)]
struct AppState {
    analytics: Arc<AnalyticsDb>,
    policy: Arc<RwLock<PolicyEngine>>,
    blocklist: Arc<RwLock<BlocklistManager>>,
    fallback: Arc<RwLock<FallbackEngine>>,
    anomaly: Arc<crate::anomaly::AnomalyDetector>,
    cache: Cache<(String, u16), (Vec<u8>, Instant)>,
}

pub async fn start_web_server(
    analytics: Arc<AnalyticsDb>,
    policy: Arc<RwLock<PolicyEngine>>,
    blocklist: Arc<RwLock<BlocklistManager>>,
    fallback: Arc<RwLock<FallbackEngine>>,
    anomaly: Arc<crate::anomaly::AnomalyDetector>,
    cache: Cache<(String, u16), (Vec<u8>, Instant)>,
) -> anyhow::Result<()> {
    let state = AppState {
        analytics,
        policy,
        blocklist,
        fallback,
        anomaly,
        cache,
    };

    let app = Router::new()
        .route("/api/stats", get(get_stats))
        .route("/api/top-domains", get(get_top_domains))
        .route("/api/top-blocked", get(get_top_blocked))
        .route("/api/lists", get(get_lists))
        .route("/api/blocklists", post(post_blocklist))
        .route("/api/blocklists/:name", delete(delete_blocklist))
        .route("/api/allow", post(post_allow))
        .route("/api/deny", post(post_deny))
        .route("/api/fallback", post(post_fallback))
        .route("/api/diagnose", post(post_diagnose))
        .route("/api/policy", get(get_policy))
        .route("/api/policy/remove", post(post_policy_remove))
        .route("/api/devices", get(get_devices))
        .route("/api/schedules", get(get_schedules))
        .route("/api/logs", delete(delete_logs))
        .route("/api/schedules", post(post_schedule))
        .route("/api/schedules/:id", delete(delete_schedule))
        .route("/api/schedules/:id/toggle", put(put_schedule_toggle))
        .route("/api/risk", post(post_risk))
        .route("/api/safesearch", get(get_safesearch))
        .route("/api/safesearch", post(post_safesearch))
        .route("/api/me", get(get_my_ip))
        .route("/api/threats", get(get_threat_status))
        .route("/api/quarantine", get(get_quarantine))
        .route("/api/quarantine/:ip", delete(delete_quarantine))
        .route("/api/actions", get(get_actions))
        .route("/api/actions", post(post_action))
        .route("/api/actions/:domain", delete(delete_action))
        .route("/api/actions/logs", get(get_action_logs).delete(clear_action_logs))
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
    analytics: Arc<analytics::AnalyticsDb>,
    policy: Arc<RwLock<policy::PolicyEngine>>,
    blocklist: Arc<RwLock<blocklist::BlocklistManager>>,
) -> anyhow::Result<()> {
    use axum::{extract::Host, routing::get, response::Html};
    
    let app = Router::new()
        .route("/logo.png", get(get_logo))
        .fallback(get(move |Host(host): Host, axum::extract::Query(params): axum::extract::Query<HashMap<String, String>>, headers: axum::http::HeaderMap| {
            let policy = policy.clone();
            let blocklist = blocklist.clone();
            let analytics = analytics.clone();
            async move {
                let host_no_port = host.split(':').next().unwrap_or(&host);
                if let Some(action) = crate::actions::get_action_for_domain_db(host_no_port, &analytics) {
                    
                    // Token verification
                    if let Some(expected_token) = &action.token {
                        let provided_token = params.get("token").map(|s| s.as_str())
                            .or_else(|| headers.get("authorization").and_then(|h| h.to_str().ok()).map(|s| s.strip_prefix("Bearer ").unwrap_or(s)))
                            .map(|s| s.to_string());
                        
                        if provided_token.as_deref() != Some(expected_token.as_str()) {
                            analytics.log_action(&action.domain, "failed", Some("Unauthorized: Invalid or missing token"));
                            return Html(r#"<html><body style="background:#0f0f14; color:#ff0000; text-align:center; padding-top:20%; font-family: sans-serif;">
                               <h1>â›” Unauthorized</h1>
                               </body></html>"#.to_string());
                        }
                    }

                    let mut outcome = "success".to_string();
                    let mut detail = None;

                    match action.action_type.as_str() {
                        "webhook" => {
                            if let Some(mut url) = action.payload_url {
                                // Dynamic variable injection for webhook URL
                                for (k, v) in &params {
                                    url = url.replace(&format!("{{{}}}", k), v);
                                }
                                let method = action.method.clone().unwrap_or_else(|| "GET".to_string());
                                let domain_clone = action.domain.clone();
                                let analytics_clone = analytics.clone();
                                tokio::spawn(async move {
                                    let client = reqwest::Client::new();
                                    let req = if method.to_uppercase() == "POST" { client.post(&url) } else { client.get(&url) };
                                    match req.send().await {
                                        Ok(res) => analytics_clone.log_action(&domain_clone, "success", Some(&format!("Status: {}", res.status()))),
                                        Err(e) => analytics_clone.log_action(&domain_clone, "failed", Some(&e.to_string())),
                                    }
                                });
                                detail = Some("Webhook triggered in background".to_string());
                            }
                        }
                        "shell" => {
                            if let Some(mut cmd) = action.shell_command {
                                // Dynamic variable injection for shell
                                for (k, v) in &params {
                                    // simple sanitization to prevent basic injection
                                    let safe_v = v.replace("'", "").replace("\"", "").replace(";", "").replace("&", "");
                                    cmd = cmd.replace(&format!("{{{}}}", k), &safe_v);
                                }
                                let domain_clone = action.domain.clone();
                                let analytics_clone = analytics.clone();
                                tokio::spawn(async move {
                                    #[cfg(unix)]
                                    let mut child = tokio::process::Command::new("sh").arg("-c").arg(&cmd).spawn().expect("Failed to spawn");
                                    #[cfg(windows)]
                                    let mut child = tokio::process::Command::new("cmd").arg("/C").arg(&cmd).spawn().expect("Failed to spawn");
                                    
                                    match child.wait().await {
                                        Ok(status) => analytics_clone.log_action(&domain_clone, "success", Some(&format!("Exit: {}", status))),
                                        Err(e) => analytics_clone.log_action(&domain_clone, "failed", Some(&e.to_string())),
                                    }
                                });
                                detail = Some("Shell command spawned".to_string());
                            }
                        }
                        "html" => {
                            if let Some(file) = action.html_content {
                                analytics.log_action(&action.domain, "success", Some("Served static HTML"));
                                return Html(file); // Assume the user put the actual HTML in the DB, not a file path for this advanced version
                            }
                        }
                        _ => {
                            outcome = "failed".to_string();
                            detail = Some("Unknown action type".to_string());
                        }
                    }

                    if detail.is_none() && outcome == "success" {
                        analytics.log_action(&action.domain, &outcome, Some("Action triggered successfully"));
                    }

                    let msg = action.success_msg.unwrap_or_else(|| "Action Executed Successfully!".to_string());
                    return Html(format!(
                        r#"<html><body style="background:#0f0f14; color:#00ff00; text-align:center; padding-top:20%; font-family: sans-serif;">
                           <h1>âœ… {}</h1>
                           </body></html>"#, msg
                    ));
                }

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
struct BlocklistCreateRequest {
    name: String,
    source_url: String,
}

async fn post_blocklist(State(state): State<AppState>, Json(req): Json<BlocklistCreateRequest>) -> Json<ActionResponse> {
    let new_list = blocklist::ListMetadata {
        name: req.name.clone(),
        source_url: req.source_url.clone(),
        last_updated: None,
        checksum: None,
        enabled: true,
        rule_count: 0,
    };
    
    let blocklist_arc = state.blocklist.clone();
    let updated_lists = {
        let mut bl = blocklist_arc.write().await;
        bl.lists.push(new_list);
        
        let config_dir = config::paths::get_data_dir();
        let lists_path = config_dir.join("blocklists.json");
        let _ = std::fs::create_dir_all(&config_dir);
        if let Ok(json) = serde_json::to_string_pretty(&bl.lists) {
            let _ = std::fs::write(&lists_path, json);
        }
        
        bl.lists.clone()
    };
    
    // Spawn task to download and apply lists
    tokio::spawn(async move {
        match BlocklistManager::download_lists(updated_lists).await {
            Ok((new_lists, new_compiled)) => {
                let mut bl = blocklist_arc.write().await;
                bl.apply_update(new_lists, new_compiled);
            }
            Err(e) => {
                tracing::error!("Failed to update blocklists: {}", e);
            }
        }
    });
    
    Json(ActionResponse {
        success: true,
        message: format!("Blocklist '{}' added and download started", req.name),
    })
}

async fn delete_blocklist(State(state): State<AppState>, Path(name): Path<String>) -> Json<ActionResponse> {
    let blocklist_arc = state.blocklist.clone();
    let updated_lists = {
        let mut bl = blocklist_arc.write().await;
        let original_len = bl.lists.len();
        bl.lists.retain(|l| l.name != name);
        
        if bl.lists.len() == original_len {
            return Json(ActionResponse {
                success: false,
                message: format!("Blocklist '{}' not found", name),
            });
        }
        
        let config_dir = config::paths::get_data_dir();
        let lists_path = config_dir.join("blocklists.json");
        let _ = std::fs::create_dir_all(&config_dir);
        if let Ok(json) = serde_json::to_string_pretty(&bl.lists) {
            let _ = std::fs::write(&lists_path, json);
        }
        
        bl.lists.clone()
    };
    
    // Spawn task to re-compile lists
    tokio::spawn(async move {
        match BlocklistManager::download_lists(updated_lists).await {
            Ok((new_lists, new_compiled)) => {
                let mut bl = blocklist_arc.write().await;
                bl.apply_update(new_lists, new_compiled);
            }
            Err(e) => {
                tracing::error!("Failed to update blocklists: {}", e);
            }
        }
    });

    Json(ActionResponse {
        success: true,
        message: format!("Blocklist '{}' deleted", name),
    })
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
    state.cache.invalidate_all();
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
    state.cache.invalidate_all();
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
    state.cache.invalidate_all();
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
    let domain = req.domain.trim().to_lowercase();
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
