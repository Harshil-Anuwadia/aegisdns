use serde::Deserialize;
use std::collections::HashMap;

#[derive(Deserialize, Debug)]
struct TailscaleStatus {
    #[serde(rename = "Peer")]
    peer: Option<HashMap<String, Peer>>,
}

#[derive(Deserialize, Debug)]
struct Peer {
    #[serde(rename = "HostName")]
    host_name: String,
    #[serde(rename = "TailscaleIPs")]
    tailscale_ips: Vec<String>,
    #[serde(rename = "Online")]
    online: bool,
}

fn parse_peers(bytes: &[u8]) -> Vec<(String, String)> {
    let Ok(status) = serde_json::from_slice::<TailscaleStatus>(bytes) else { return Vec::new(); };
    status.peer.into_iter().flatten().flat_map(|(_, peer)| {
        let name = peer.host_name;
        let online = peer.online;
        peer.tailscale_ips.into_iter()
            .filter(move |ip| online && ip.parse::<std::net::Ipv4Addr>().is_ok())
            .map(move |ip| (ip, name.clone()))
    }).collect()
}

#[cfg(unix)]
async fn status_from_localapi() -> Option<Vec<u8>> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let path = std::env::var("AEGIS_TAILSCALE_SOCKET")
        .unwrap_or_else(|_| "/var/run/tailscale/tailscaled.sock".into());
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        tokio::net::UnixStream::connect(path),
    ).await.ok()?.ok()?;
    stream.write_all(b"GET /localapi/v0/status HTTP/1.1\r\nHost: local-tailscaled.sock\r\nSec-Tailscale: localapi\r\nConnection: close\r\n\r\n").await.ok()?;
    let mut response = Vec::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(3),
        (&mut stream).take(8 * 1024 * 1024).read_to_end(&mut response),
    ).await.ok()?.ok()?;
    http_body(&response)
}

#[cfg(unix)]
fn http_body(response: &[u8]) -> Option<Vec<u8>> {
    let split = response.windows(4).position(|w| w == b"\r\n\r\n")?;
    let headers = std::str::from_utf8(&response[..split]).ok()?.to_ascii_lowercase();
    if !headers.lines().next()?.contains(" 200 ") { return None; }
    let body = &response[split + 4..];
    if headers.lines().any(|line| line == "transfer-encoding: chunked") {
        decode_chunked(body)
    } else {
        Some(body.to_vec())
    }
}

#[cfg(unix)]
fn decode_chunked(mut input: &[u8]) -> Option<Vec<u8>> {
    let mut output = Vec::new();
    loop {
        let line_end = input.windows(2).position(|w| w == b"\r\n")?;
        let size_text = std::str::from_utf8(&input[..line_end]).ok()?.split(';').next()?;
        let size = usize::from_str_radix(size_text.trim(), 16).ok()?;
        input = &input[line_end + 2..];
        if size == 0 { return Some(output); }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" { return None; }
        output.extend_from_slice(&input[..size]);
        if output.len() > 8 * 1024 * 1024 { return None; }
        input = &input[size + 2..];
    }
}

fn status_from_cli() -> Option<Vec<u8>> {
    let output = std::process::Command::new("tailscale").args(["status", "--json"]).output().ok()?;
    output.status.success().then_some(output.stdout)
}

pub async fn get_online_peers() -> Vec<(String, String)> {
    #[cfg(unix)]
    if let Some(status) = status_from_localapi().await {
        return parse_peers(&status);
    }
    let status = tokio::task::spawn_blocking(status_from_cli).await.ok().flatten();
    status.map_or_else(Vec::new, |bytes| parse_peers(&bytes))
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_online_ipv4_peers_only() {
        let json = br#"{"Peer":{"a":{"HostName":"phone","TailscaleIPs":["100.64.0.2","fd7a::2"],"Online":true},"b":{"HostName":"off","TailscaleIPs":["100.64.0.3"],"Online":false}}}"#;
        assert_eq!(super::parse_peers(json), vec![("100.64.0.2".into(), "phone".into())]);
    }

    #[cfg(unix)]
    #[test]
    fn decodes_chunked_localapi_response() {
        let response=b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";
        assert_eq!(super::http_body(response).unwrap(), b"test");
    }
}
