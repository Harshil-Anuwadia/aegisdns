use std::path::PathBuf;
use serde::{Serialize, Deserialize};
use tokio::sync::RwLock;
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TelegramConfig {
    pub enabled: bool,
    pub bot_token: String,
    pub chat_id: String,
    /// Minimum risk score (0-100) to trigger alert. Default 70.
    pub threat_threshold: u8,
    /// Also notify on every blocked query (can be noisy). Default false.
    pub notify_blocked: bool,
}

/// Structured context for one DNS notification. Formatting lives here rather
/// than at the query call site so every alert has the same readable contract.
#[derive(Debug, Clone)]
pub struct DnsAlert {
    pub domain: String,
    pub client_ip: String,
    pub device_name: Option<String>,
    pub query_type: String,
    pub transport: &'static str,
    pub blocked: bool,
    pub resolution_failed: bool,
    pub block_reason: Option<String>,
    pub risk_score: u8,
    pub risk_level: &'static str,
    pub risk_factors: Vec<String>,
}

impl DnsAlert {
    fn dedupe_key(&self) -> String {
        format!(
            "{}:{}:{}:{}:{}",
            self.client_ip, self.domain, self.query_type, self.blocked, self.resolution_failed
        )
    }
}

/// Produce compact Telegram HTML with enough context to make the alert useful
/// without opening the dashboard. All query-derived values are escaped.
pub fn format_dns_alert(alert: &DnsAlert) -> String {
    let title = if alert.blocked {
        "🛡️ <b>DNS request blocked</b>"
    } else if alert.resolution_failed {
        "❗ <b>High-risk DNS request failed</b>"
    } else if alert.risk_score >= 85 {
        "🚨 <b>Critical DNS risk detected</b>"
    } else {
        "⚠️ <b>High-risk DNS request allowed</b>"
    };
    let domain = config::html_escape(&alert.domain);
    let client = config::html_escape(&alert.client_ip);
    let query_type = config::html_escape(&alert.query_type);
    let risk_level = config::html_escape(alert.risk_level);
    let device = match alert.device_name.as_deref() {
        Some(name) => format!("{} · <code>{client}</code>", config::html_escape(name)),
        None => format!("<code>{client}</code>"),
    };

    let mut message = format!(
        "{title}\n\n<b>Domain</b>  <code>{domain}</code>\n<b>Device</b>  {device}\n<b>Query</b>  {query_type} · {}\n<b>Risk</b>  {risk_level} · {}/100",
        alert.transport, alert.risk_score
    );
    if let Some(reason) = alert.block_reason.as_deref() {
        message.push_str(&format!("\n<b>Reason</b>  {}", config::html_escape(reason)));
    }

    let factors: Vec<String> = alert
        .risk_factors
        .iter()
        .filter(|factor| !factor.starts_with("No significant") && !factor.starts_with("Trusted"))
        .take(3)
        .map(|factor| format!("• {}", config::html_escape(factor)))
        .collect();
    if !factors.is_empty() {
        message.push_str("\n\n<b>Why it was flagged</b>\n");
        message.push_str(&factors.join("\n"));
    }

    if alert.blocked {
        message.push_str("\n\n<b>Outcome</b>  AegisDNS returned NXDOMAIN. No destination was provided.");
    } else if alert.resolution_failed {
        message.push_str("\n\n<b>Outcome</b>  Resolution failed with SERVFAIL. No destination was provided.");
    } else {
        message.push_str("\n\n<b>Outcome</b>  Allowed by the current policy. Review the domain if this traffic is unexpected.");
    }
    message.push_str("\n\n<i>Review in AegisDNS → Traffic</i>");
    message
}

pub fn format_test_message() -> &'static str {
    "✅ <b>AegisDNS alerts are ready</b>\n\nTelegram delivery is working. Future alerts will identify the domain, device, query type, policy outcome, risk score, and detection signals.\n\n<i>You can change the threshold in AegisDNS → Alerts.</i>"
}

fn config_path() -> PathBuf {
    config::paths::get_data_dir().join("telegram.json")
}

pub fn load_config() -> TelegramConfig {
    let path = config_path();
    if path.exists() {
        match std::fs::read_to_string(&path) {
            Ok(data) => match serde_json::from_str(&data) {
                Ok(cfg) => return cfg,
                Err(e) => warn!("Failed to parse telegram.json: {}", e),
            },
            Err(e) => warn!("Failed to read telegram.json: {}", e),
        }
    }
    TelegramConfig {
        enabled: false,
        bot_token: String::new(),
        chat_id: String::new(),
        threat_threshold: 70,
        notify_blocked: false,
    }
}

pub fn save_config(cfg: &TelegramConfig) -> Result<(), String> {
    let path = config_path();
    let data = serde_json::to_string_pretty(cfg)
        .map_err(|e| format!("Serialize error: {}", e))?;
    config::atomic_write(&path, data)
        .map_err(|e| format!("Write error: {}", e))?;
    Ok(())
}

/// Telegram's published Bot API endpoint, used as a DNS bypass.
///
/// Resolving `api.telegram.org` normally would send the daemon's own alert
/// traffic back through the DNS proxy it is reporting on: the lookups would be
/// logged as user queries, and an outage or a block rule could stop the very
/// alerts meant to report it. Pinning the address avoids that circular
/// dependency. It is only a *hint* — `resolve()` overrides DNS but TLS still
/// validates the `api.telegram.org` certificate, so a stale or hijacked
/// address cannot yield a trusted connection.
///
/// Override with `AEGIS_TELEGRAM_ADDR` (`host:port`) if Telegram renumbers or
/// the deployment routes through an egress proxy.
const TELEGRAM_API_ADDR: &str = "149.154.167.220:443";

/// Build a reqwest client for Telegram API calls.
///
/// Built once and reused: a `reqwest::Client` owns a connection pool, and
/// constructing a new one per request threw away every pooled TLS session.
pub fn build_telegram_client() -> Result<reqwest::Client, String> {
    static CLIENT: std::sync::OnceLock<Result<reqwest::Client, String>> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        let configured = std::env::var("AEGIS_TELEGRAM_ADDR").unwrap_or_default();
        let addr = if configured.trim().is_empty() { TELEGRAM_API_ADDR } else { configured.trim() };

        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .connect_timeout(std::time::Duration::from_secs(10));

        // An unparseable address must not panic the daemon. Fall back to
        // ordinary DNS resolution, which still works — it is just noisier.
        match addr.parse::<std::net::SocketAddr>() {
            Ok(socket) => builder = builder.resolve("api.telegram.org", socket),
            Err(e) => warn!("Ignoring invalid Telegram API address {addr:?} ({e}); using DNS resolution"),
        }

        builder.build().map_err(|e|format!("Failed to build bounded Telegram client: {e}"))
    })
    .clone()
}

/// Non-blocking alert — spawns a Tokio task so DNS is never delayed. Repeated
/// copies of the same device/domain/query outcome are quieted for five minutes,
/// while unrelated alerts remain eligible for immediate delivery.
pub fn send_dns_alert(cfg: Arc<RwLock<TelegramConfig>>, alert: DnsAlert) {
    static LIMIT: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    static RECENT: std::sync::OnceLock<moka::sync::Cache<String, ()>> = std::sync::OnceLock::new();
    let Ok(permit) = LIMIT.get_or_init(||Arc::new(tokio::sync::Semaphore::new(4))).clone().try_acquire_owned() else { return; };
    let recent = RECENT.get_or_init(||moka::sync::Cache::builder()
        .max_capacity(10_000)
        .time_to_live(std::time::Duration::from_secs(300))
        .build());
    let key = alert.dedupe_key();
    if recent.get(&key).is_some() { return; }
    recent.insert(key, ());
    let message = format_dns_alert(&alert);
    tokio::spawn(async move {
        let _permit = permit;
        let cfg = cfg.read().await.clone();
        if !cfg.enabled || cfg.bot_token.is_empty() || cfg.chat_id.is_empty() {
            return;
        }
        match send_message(&cfg, &message).await {
            Ok(()) => info!("Telegram alert sent successfully"),
            Err(e) => warn!("Telegram send failed: {}", e),
        }
    });
}

/// Strip a bot token out of text before it is logged or returned to a client.
///
/// The token is part of the request URL, and `reqwest` includes the URL in its
/// error messages. Those errors were being forwarded verbatim into log lines
/// and HTTP responses, which disclosed the credential to anyone who could read
/// either. Telegram tokens look like `<digits>:<base64-ish>`.
fn redact_token(text: &str, token: &str) -> String {
    if token.is_empty() {
        return text.to_string();
    }
    text.replace(token, "<redacted>")
}

pub async fn send_message(cfg: &TelegramConfig, message: &str) -> Result<(), String> {
    let url = format!("https://api.telegram.org/bot{}/sendMessage", cfg.bot_token);
    let response = build_telegram_client()?
        .post(&url)
        .json(&serde_json::json!({
            "chat_id": cfg.chat_id,
            "text": message,
            "parse_mode": "HTML"
        }))
        .send()
        .await
        .map_err(|e| format!("Failed to reach Telegram API: {}", redact_token(&e.to_string(), &cfg.bot_token)))?;
    if response.status().is_success() {
        Ok(())
    } else {
        Err(format!("Telegram API returned {}", response.status()))
    }
}

/// Proxy a getUpdates call to Telegram — used by the web UI's auto-detect.
/// Done server-side to avoid browser CORS restrictions on api.telegram.org.
pub async fn proxy_get_updates(token: &str) -> Result<serde_json::Value, String> {
    let url    = format!("https://api.telegram.org/bot{}/getUpdates", token);
    let client = build_telegram_client()?;
    match client.get(&url).send().await {
        Ok(resp) => resp.json::<serde_json::Value>().await
            .map_err(|e| format!("Failed to parse Telegram response: {}", redact_token(&e.to_string(), token))),
        Err(e) => Err(format!("Failed to reach Telegram API: {}", redact_token(&e.to_string(), token))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A leaked bot token lets anyone impersonate the notification bot, so it
    /// must never survive into an error string.
    #[test]
    fn token_is_removed_from_error_text() {
        let token = "123456789:AAF-ExampleTokenValueForTesting1234";
        let error = format!("error sending request for url (https://api.telegram.org/bot{token}/sendMessage)");
        let redacted = redact_token(&error, token);
        assert!(!redacted.contains(token), "token must not appear: {redacted}");
        assert!(redacted.contains("<redacted>"));
    }

    /// An unconfigured bot has an empty token; redaction must not corrupt the
    /// message by replacing every empty substring.
    #[test]
    fn empty_token_leaves_text_unchanged() {
        assert_eq!(redact_token("connection refused", ""), "connection refused");
    }

    #[test]
    fn blocked_alert_is_specific_and_escapes_untrusted_values() {
        let message = format_dns_alert(&DnsAlert {
            domain: "login-<fake>.xyz".into(),
            client_ip: "192.0.2.10".into(),
            device_name: Some("Living Room <TV>".into()),
            query_type: "A".into(),
            transport: "UDP",
            blocked: true,
            resolution_failed: false,
            block_reason: Some("Phishing protection".into()),
            risk_score: 92,
            risk_level: "Critical",
            risk_factors: vec!["Suspicious keyword: 'login'".into()],
        });

        assert!(message.contains("DNS request blocked"));
        assert!(message.contains("Living Room &lt;TV&gt;"));
        assert!(message.contains("login-&lt;fake&gt;.xyz"));
        assert!(message.contains("Phishing protection"));
        assert!(message.contains("AegisDNS returned NXDOMAIN"));
        assert!(!message.contains("<fake>"));
    }

    #[test]
    fn allowed_threat_alert_explains_that_policy_did_not_block_it() {
        let message = format_dns_alert(&DnsAlert {
            domain: "account-check.example".into(),
            client_ip: "192.0.2.11".into(),
            device_name: None,
            query_type: "AAAA".into(),
            transport: "TCP",
            blocked: false,
            resolution_failed: false,
            block_reason: None,
            risk_score: 78,
            risk_level: "High",
            risk_factors: vec!["Suspicious keyword: 'account'".into()],
        });

        assert!(message.contains("High-risk DNS request allowed"));
        assert!(message.contains("Allowed by the current policy"));
        assert!(message.contains("192.0.2.11"));
        assert!(message.contains("AAAA · TCP"));
    }

    #[test]
    fn alert_dedupe_is_scoped_to_the_same_event() {
        let first = DnsAlert {
            domain: "one.example".into(),
            client_ip: "192.0.2.12".into(),
            device_name: None,
            query_type: "A".into(),
            transport: "UDP",
            blocked: true,
            resolution_failed: false,
            block_reason: Some("Active blocklist".into()),
            risk_score: 0,
            risk_level: "Safe",
            risk_factors: vec![],
        };
        let mut second = first.clone();
        second.domain = "two.example".into();
        assert_ne!(first.dedupe_key(), second.dedupe_key());
    }
}
