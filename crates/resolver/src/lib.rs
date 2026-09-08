use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::fs;

pub struct UnboundManager {
    pub process: Option<Child>,
}

/// Address used by the policy proxy for recursive lookups.
/// Unix deployments use the supervised, validating Unbound instance. Native
/// Windows builds currently use a direct public fallback because Unbound is
/// not bundled there.
pub fn proxy_upstream_addr() -> &'static str {
    #[cfg(windows)]
    { "8.8.8.8:53" }
    #[cfg(not(windows))]
    { "127.0.0.1:5353" }
}

impl UnboundManager {
    pub fn new() -> Self {
        Self { process: None }
    }

    pub async fn start(&mut self) -> anyhow::Result<()> {
        #[cfg(windows)]
        {
            tracing::warn!("Unbound is not bundled for native Windows; forwarding to 8.8.8.8 without local DNSSEC validation");
            return Ok(());
        }

        #[cfg(unix)]
        {
            let conf_path = "/run/aegisdns/unbound.conf";
            let anchor = config::paths::get_data_dir().join("root.key");
            let anchor_path = anchor.to_str().ok_or_else(|| anyhow::anyhow!("Invalid data path"))?;

            // Ensure directory exists
            let _ = fs::create_dir_all("/run/aegisdns").await;

            // Download DNSSEC root trust anchor only if it doesn't exist yet.
            // Running this on every restart is wasteful and can be rate-limited.
            if !std::path::Path::new(anchor_path).exists() {
                tracing::info!("[SECURITY] Downloading DNSSEC root trust anchor...");
                let _ = Command::new("unbound-anchor")
                    .arg("-a")
                    .arg(anchor_path)
                    .status()
                    .await;
            }

            // Read resolver config to honour user's IPv6 preference.
            // Default: upstream IPv6 disabled (Jio's IPv6 peering to root/TLD servers
            // adds 1-3s of extra latency before falling back to IPv4).
            // Users on ISPs with good IPv6 peering can set `"ipv6": true` in config.json.
            let resolver_cfg = config::load_main_config()
                .map(|c| c.resolver)
                .unwrap_or_default();
            let do_ip6 = if resolver_cfg.ipv6 { "yes" } else { "no" };

            let mut conf_data = format!(r#"
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5353

    # ── Answering clients ──
    do-ip4: yes
    do-udp: yes
    do-tcp: yes

    # ── Outgoing upstream IPv6 ──
    # Controlled by the 'ipv6' field in config.json (resolver section).
    # Defaults to 'no'. If your ISP has reliable IPv6 peering set it to true.
    do-ip6: {do_ip6}

    # ── Threading for parallel resolution ──
    num-threads: 4
    so-reuseport: yes
    msg-cache-slabs: 4
    rrset-cache-slabs: 4
    infra-cache-slabs: 4
    key-cache-slabs: 4

    # ── Cache sizing (bigger = more hits = lower latency) ──
    msg-cache-size: 128m
    rrset-cache-size: 256m
    key-cache-size: 32m
    infra-cache-numhosts: 50000

    # Respect authoritative TTLs, including zero.
    cache-min-ttl: 0

    # Stale responses are disabled until explicitly configured with operational limits.
    serve-expired: no
    serve-expired-ttl: 86400
    serve-expired-reply-ttl: 30

    # ── Prefetch: refresh popular entries before they expire ──
    prefetch: yes
    prefetch-key: yes

    # ── DNSSEC ──
    harden-dnssec-stripped: yes
    auto-trust-anchor-file: "{anchor_path}"
    aggressive-nsec: yes
    val-permissive-mode: no

    # ── Privacy / hardening ──
    qname-minimisation: yes
    use-caps-for-id: yes
    hide-identity: yes
    hide-version: yes
    chroot: ""
    pidfile: ""
    username: ""

    # ── Block private addresses from being returned in public DNS answers ──
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: 172.16.0.0/12
    private-address: 10.0.0.0/8
    private-address: fc00::/7
    private-address: 127.0.0.0/8
    private-address: 100.64.0.0/10
    private-address: ::ffff:0:0/96
    private-address: fe80::/10
    tls-cert-bundle: /etc/ssl/certs/ca-certificates.crt
"#, anchor_path = anchor_path, do_ip6 = do_ip6);
        let upstream = config::upstream::UpstreamDnsConfig::load().unwrap_or_else(|e| {
            tracing::error!("Invalid forwarding config, using local recursion: {}", e);
            Default::default()
        });
        conf_data.push_str(&upstream.unbound_config()?);
        fs::write(conf_path, conf_data).await?;

        // Spawn Unbound process
        let child = Command::new("unbound")
            .arg("-c")
            .arg(conf_path)
            .arg("-d") // Run in foreground so daemon can manage its lifecycle
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
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
