use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct MobileAccess {
    pub success: bool,
    pub available: bool,
    pub enabled: bool,
    #[serde(default)]
    pub conflict: bool,
    pub url: Option<String>,
    pub dns_name: Option<String>,
    pub message: String,
}

pub async fn request(action: &str) -> MobileAccess {
    let unavailable = |message: String| MobileAccess {
        success: action == "status",
        available: false,
        enabled: false,
        conflict: false,
        url: None,
        dns_name: None,
        message,
    };
    if !matches!(action, "status" | "enable" | "disable") {
        return unavailable("Unsupported mobile access request.".into());
    }
    let result = tokio::time::timeout(std::time::Duration::from_secs(35), async {
        let mut stream = tokio::net::TcpStream::connect("127.0.0.1:5382").await?;
        stream
            .write_all(format!("{{\"action\":\"{action}\"}}\n").as_bytes())
            .await?;
        stream.shutdown().await?;
        let mut line = String::new();
        BufReader::new(stream)
            .take(64 * 1024)
            .read_line(&mut line)
            .await?;
        serde_json::from_str::<MobileAccess>(&line)
            .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
    })
    .await;
    match result {
        Ok(Ok(status)) => status,
        Ok(Err(_)) => unavailable("One-click mobile access is not installed on this host.".into()),
        Err(_) => unavailable("Tailscale did not finish the mobile access request in time.".into()),
    }
}
