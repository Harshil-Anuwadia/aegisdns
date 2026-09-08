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

/// Build a reqwest client that bypasses DNS for api.telegram.org.
/// This prevents the daemon's own Telegram calls from going through our
/// DNS proxy (which would log them as user queries and risk circular deps).
/// IP 149.154.167.220 is Telegram's primary Bot API endpoint.
pub fn build_telegram_client() -> reqwest::Client {
    reqwest::Client::builder()
        .resolve("api.telegram.org", "149.154.167.220:443".parse().unwrap())
        .timeout(std::time::Duration::from_secs(15))
        .build()
        .unwrap_or_default()
}

/// Non-blocking alert — spawns a tokio task so DNS is never delayed.
pub fn send_alert(cfg: Arc<RwLock<TelegramConfig>>, message: String) {
    static LIMIT: std::sync::OnceLock<Arc<tokio::sync::Semaphore>> = std::sync::OnceLock::new();
    static LAST: std::sync::OnceLock<std::sync::Mutex<Option<std::time::Instant>>> = std::sync::OnceLock::new();
    let Ok(permit) = LIMIT.get_or_init(||Arc::new(tokio::sync::Semaphore::new(2))).clone().try_acquire_owned() else { return; };
    {
        let mut last = LAST.get_or_init(||std::sync::Mutex::new(None)).lock().unwrap();
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
        .map_err(|e| format!("Failed to reach Telegram API: {e}"))?;
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
            .map_err(|e| format!("Failed to parse Telegram response: {}", e)),
        Err(e) => Err(format!("Failed to reach Telegram API: {}", e)),
    }
}
