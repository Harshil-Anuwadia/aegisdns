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

            // Every switch in the `resolver` section of config.json is applied
            // here. They used to be parsed and then thrown away except for
            // `ipv6`, so changing `dnssec`, `ipv4`, `qname_minimisation` or
            // `cache` had no observable effect.
            let cfg = config::load_main_config().map(|c| c.resolver).unwrap_or_default();

            // Disabling both address families would leave Unbound unable to
            // reach any authoritative server. Keep IPv4 in that case.
            let (want_ip4, want_ip6) = if !cfg.ipv4 && !cfg.ipv6 {
                tracing::warn!("config.json disables both ipv4 and ipv6; keeping IPv4 enabled so resolution still works");
                (true, false)
            } else {
                (cfg.ipv4, cfg.ipv6)
            };
            let yes_no = |on: bool| if on { "yes" } else { "no" };
            let (do_ip4, do_ip6) = (yes_no(want_ip4), yes_no(want_ip6));
            let qname_min = yes_no(cfg.qname_minimisation);

            // Unbound only validates when the validator module is loaded and a
            // trust anchor is present, so turning DNSSEC off has to remove both.
            let dnssec_block = if cfg.dnssec {
                [
                    "    module-config: \"validator iterator\"",
                    "    harden-dnssec-stripped: yes",
                    &format!("    auto-trust-anchor-file: \"{anchor_path}\""),
                    "    aggressive-nsec: yes",
                    "    val-permissive-mode: no",
                ]
                .join("\n")
            } else {
                tracing::warn!("DNSSEC validation is disabled in config.json; responses will not be cryptographically verified");
                "    module-config: \"iterator\"".to_string()
            };

            // A zero-sized cache is how Unbound expresses "do not cache".
            // Prefetch is emitted here too: it only makes sense with a cache,
            // and declaring it twice would be a duplicate directive.
            let cache_block = if cfg.cache {
                [
                    "    msg-cache-size: 128m",
                    "    rrset-cache-size: 256m",
                    "    key-cache-size: 32m",
                    "    prefetch: yes",
                    "    prefetch-key: yes",
                ]
                .join("\n")
            } else {
                [
                    "    msg-cache-size: 0",
                    "    rrset-cache-size: 0",
                    "    key-cache-size: 0",
                    "    prefetch: no",
                    "    prefetch-key: no",
                ]
                .join("\n")
            };

            let mut conf_data = format!(r#"
server:
    verbosity: 1
    interface: 127.0.0.1
    port: 5353

    # ── Address families used to reach upstream servers ──
    # Both are controlled by the 'ipv4'/'ipv6' fields in the resolver section
    # of config.json. Some ISPs have poor IPv6 peering to the root and TLD
    # servers, which adds seconds of latency before falling back to IPv4;
    # set "ipv6": false there if that describes your connection.
    do-ip4: {do_ip4}
    do-ip6: {do_ip6}
    do-udp: yes
    do-tcp: yes

    # ── Threading for parallel resolution ──
    num-threads: 4
    so-reuseport: yes
    msg-cache-slabs: 4
    rrset-cache-slabs: 4
    infra-cache-slabs: 4
    key-cache-slabs: 4

    # ── Cache sizing and prefetch (from the 'cache' field in config.json) ──
    # Bigger cache = more hits = lower latency; zeroed when caching is off.
{cache_block}
    infra-cache-numhosts: 50000

    # Respect authoritative TTLs, including zero.
    cache-min-ttl: 0

    # Stale responses are disabled until explicitly configured with operational limits.
    serve-expired: no
    serve-expired-ttl: 86400
    serve-expired-reply-ttl: 30

    # ── DNSSEC (from the 'dnssec' field in config.json) ──
{dnssec_block}
    # ── Privacy / hardening ──
    qname-minimisation: {qname_min}
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
"#);
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
