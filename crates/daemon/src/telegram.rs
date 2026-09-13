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
pub fn build_telegram_client() -> reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
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

        builder.build().unwrap_or_else(|e| {
            // The configured timeouts are lost in this path, so say so rather
            // than silently degrading to an unbounded default client.
            warn!("Falling back to a default HTTP client for Telegram: {e}");
            reqwest::Client::new()
        })
    })
    .clone()
}

/// Non-blocking alert — spawns a tokio task so DNS is never delayed.
pub fn send_alert(cfg: Arc<RwLock<TelegramConfig>>, message: String) {
    static LIMIT: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    static LAST: std::sync::OnceLock<std::sync::Mutex<Option<std::time::Instant>>> = std::sync::OnceLock::new();
    let Ok(permit) = LIMIT.get_or_init(||Arc::new(tokio::sync::Semaphore::new(2))).clone().try_acquire_owned() else { return; };
    {
        // Recover from poisoning: a panic elsewhere must not permanently
        // disable alerting, and the guarded value is a single Instant.
        let mut last = LAST.get_or_init(||std::sync::Mutex::new(None)).lock().unwrap_or_else(|e|e.into_inner());
        if last.is_some_and(|t|t.elapsed() < std::time::Duration::from_secs(5)) { return; }
        *last = Some(std::time::Instant::now());
    }
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
    let response = build_telegram_client()
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
    let client = build_telegram_client();
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
}
