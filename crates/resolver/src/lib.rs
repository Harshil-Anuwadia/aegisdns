use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::fs;

pub struct UnboundManager {
    pub process: Option<Child>,
}

impl UnboundManager {
    pub fn new() -> Self {
        Self { process: None }
    }
    
    pub async fn start(&mut self) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            tracing::warn!("Unbound resolver is not natively bundled for Windows yet. Using public upstream 8.8.8.8 as fallback.");
            return Ok(());
        }

        #[cfg(unix)]
        {
            let conf_path = "/run/aegisdns/unbound.conf";
            let anchor_path = "/run/aegisdns/root.key";
            
            // Ensure directory exists
            let _ = fs::create_dir_all("/run/aegisdns").await;
            
            // Download DNSSEC root trust anchor only if it doesn't exist yet.
            // Running this on every restart is wasteful and can be rate-limited.
            if !std::path::Path::new(anchor_path).exists() {
                eprintln!("[aegisdns] Downloading DNSSEC root trust anchor...");
                let _ = Command::new("unbound-anchor")
                    .arg("-a")
                    .arg(anchor_path)
                    .status()
                    .await;
            }

            let conf_data = format!(r#"
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5353
    do-ip4: yes
    do-ip6: yes
    do-udp: yes
    do-tcp: yes
    qname-minimisation: yes
    harden-dnssec-stripped: yes
    auto-trust-anchor-file: "{}"
    aggressive-nsec: yes
    val-permissive-mode: no
    prefetch: yes
    use-caps-for-id: yes
    hide-identity: yes
    hide-version: yes
    chroot: ""
    pidfile: ""
    username: ""
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fd00::/8
    private-address: fe80::/10
"#, anchor_path);
        fs::write(conf_path, conf_data).await?;

        // Spawn Unbound process
        let child = Command::new("unbound")
            .arg("-c")
            .arg(conf_path)
            .arg("-d") // Run in foreground so daemon can manage its lifecycle
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
            
            self.process = Some(child);
            Ok(())
        }
    }
    
    pub async fn stop(&mut self) -> anyhow::Result<()> {
        if let Some(mut child) = self.process.take() {
            let _ = child.kill().await;
        }
        Ok(())
    }
}
