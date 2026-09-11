pub mod paths;
use serde::{Deserialize, Serialize};

pub fn iter_subdomains(domain: &str) -> impl Iterator<Item = &str> {
    let mut current = Some(domain);
    std::iter::from_fn(move || {
        let ret = current;
        if let Some(d) = current {
            if let Some(idx) = d.find('.') {
                let suffix = &d[idx + 1..];
                if suffix.is_empty() {
                    current = None;
                } else {
                    current = Some(suffix);
                }
            } else {
                current = None;
            }
        }
        ret
    })
}

/// Contents of `config.json`.
///
/// Every field is optional: `#[serde(default)]` means a config that only sets
/// `host_ips` (as shipped in `config.example.json`) still parses, and any
/// section the user omits falls back to the documented defaults. Without this
/// the whole file was rejected for a missing `resolver` key and every setting
/// in it was silently ignored.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct AegisConfig {
    /// Addresses of this host that the daemon may answer for. The first
    /// non-loopback IPv4 entry is used for blocked-page and action responses.
    pub host_ips: Vec<String>,
    pub resolver: ResolverConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ResolverConfig {
    pub dnssec: bool,
    pub qname_minimisation: bool,
    pub ipv4: bool,
    pub ipv6: bool,
    pub cache: bool,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            dnssec: true,
            qname_minimisation: true,
            ipv4: true,
            ipv6: true,
            cache: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyConfig {
    pub profile: String,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            profile: "balanced".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = AegisConfig::default();
        assert_eq!(config.policy.profile, "balanced");
        assert!(config.resolver.dnssec);
        assert!(config.resolver.qname_minimisation);
    }

    /// The shipped example only sets `host_ips`. It must still parse: when the
    /// required-field version of this struct rejected it, `load_main_config`
    /// returned None and every resolver setting silently reverted to default.
    #[test]
    fn host_ips_only_config_parses_with_defaults() {
        let config: AegisConfig =
            serde_json::from_str(r#"{"host_ips":["192.168.1.10"]}"#).expect("must parse");
        assert_eq!(config.host_ips, vec!["192.168.1.10".to_string()]);
        assert!(config.resolver.dnssec, "omitted sections keep their defaults");
        assert_eq!(config.policy.profile, "balanced");
    }

    /// A partially specified section must override only the keys it names.
    #[test]
    fn partial_resolver_section_overrides_only_named_keys() {
        let config: AegisConfig =
            serde_json::from_str(r#"{"resolver":{"ipv6":false}}"#).expect("must parse");
        assert!(!config.resolver.ipv6, "explicit value wins");
        assert!(config.resolver.ipv4, "unnamed keys keep defaults");
        assert!(config.resolver.cache);
    }

    /// An empty object is a valid config equivalent to all defaults.
    #[test]
    fn empty_config_object_is_valid() {
        let config: AegisConfig = serde_json::from_str("{}").expect("must parse");
        assert!(config.host_ips.is_empty());
        assert_eq!(config.policy.profile, "balanced");
    }

    /// The file the repository ships to users must be loadable by the daemon.
    #[test]
    fn shipped_example_config_is_loadable() {
        let example = concat!(env!("CARGO_MANIFEST_DIR"), "/../../config.example.json");
        let text = std::fs::read_to_string(example).expect("config.example.json must exist");
        let config: AegisConfig =
            serde_json::from_str(&text).expect("config.example.json must deserialize");
        assert!(
            config.host_ips.iter().any(|ip| ip.parse::<std::net::Ipv4Addr>().is_ok()),
            "the example must show at least one valid host IP"
        );
    }

    /// `AEGIS_CONFIG` is an absolute override and must be the only candidate.
    #[test]
    fn explicit_env_override_is_the_only_candidate() {
        // Safety: single-threaded assertion on a process-global; the value is
        // restored before returning so other tests are unaffected.
        let previous = std::env::var_os("AEGIS_CONFIG");
        std::env::set_var("AEGIS_CONFIG", "/tmp/aegis-test-config.json");
        let candidates = config_candidates();
        match previous {
            Some(value) => std::env::set_var("AEGIS_CONFIG", value),
            None => std::env::remove_var("AEGIS_CONFIG"),
        }
        assert_eq!(candidates, vec![std::path::PathBuf::from("/tmp/aegis-test-config.json")]);
    }

    #[test]
    fn canonical_domain_normalises_case_and_root_label() {
        assert_eq!(canonical_domain("  Example.COM.  "), "example.com");
    }

    #[test]
    fn valid_domain_rejects_malformed_input() {
        assert!(valid_domain("example.com"));
        assert!(valid_domain("*.example.com"));
        assert!(!valid_domain(""));
        assert!(!valid_domain("exa mple.com"), "spaces are not allowed");
        assert!(!valid_domain("example..com"), "empty labels are not allowed");
        assert!(!valid_domain(&"a".repeat(64)), "labels cap at 63 bytes");
    }

    #[test]
    fn html_escape_neutralises_markup() {
        assert_eq!(
            html_escape(r#"<script>alert("x")</script>"#),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;"
        );
    }
}

/// Candidate locations for `config.json`, in priority order.
///
/// 1. `$AEGIS_CONFIG` — explicit override, always wins.
/// 2. `<data dir>/config.json` — the native/package install location.
/// 3. `/app/config.json` — where `docker-compose.yml` bind-mounts the file.
///
/// Before this list existed the loader only looked at (2) while the daemon's
/// own host-IP lookup only looked at (1) with a *relative* default, so a
/// container deployment satisfied neither and every documented setting in
/// `config.json` was quietly ignored.
pub fn config_candidates() -> Vec<std::path::PathBuf> {
    if let Some(explicit) = std::env::var_os("AEGIS_CONFIG") {
        return vec![std::path::PathBuf::from(explicit)];
    }
    let mut paths = vec![paths::get_data_dir().join("config.json")];
    if cfg!(unix) {
        paths.push(std::path::PathBuf::from("/app/config.json"));
    }
    paths
}

/// Load `config.json` from the first candidate location that exists.
///
/// Returns `None` only when no config file is present; callers then fall back
/// to `Default`. A file that exists but cannot be parsed is reported loudly
/// rather than silently ignored, because a typo previously downgraded the
/// user's settings to defaults with no diagnostic at all.
pub fn load_main_config() -> Option<AegisConfig> {
    for path in config_candidates() {
        let data = match std::fs::read_to_string(&path) {
            Ok(data) => data,
            Err(error) => {
                if error.kind() != std::io::ErrorKind::NotFound {
                    eprintln!("aegisdns: cannot read {}: {error}", path.display());
                }
                continue;
            }
        };
        return match serde_json::from_str::<AegisConfig>(&data) {
            Ok(config) => Some(config),
            Err(error) => {
                eprintln!(
                    "aegisdns: {} is not valid JSON ({error}); using built-in defaults",
                    path.display()
                );
                None
            }
        };
    }
    None
}

/// Canonical representation for all rule and DNS comparisons.
pub fn canonical_domain(domain: &str) -> String {
    domain.trim().trim_end_matches('.').to_ascii_lowercase()
}

pub fn valid_domain(domain: &str) -> bool {
    let d = domain.strip_prefix("*.").unwrap_or(domain);
    !d.is_empty() && d.len() <= 253 && d.split('.').all(|l| !l.is_empty() && l.len() <= 63 && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
}

pub fn html_escape(value: &str) -> String {
    value.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;").replace('\'', "&#39;")
}

/// Write privately and atomically; a crash cannot leave a partially truncated config.
pub fn atomic_write(path: impl AsRef<std::path::Path>, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    use std::io::Write;
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let path = path.as_ref();
    if let Some(parent) = path.parent() { std::fs::create_dir_all(parent)?; }
    let suffix = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp-{}-{}", std::process::id(), suffix));
    let result = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
        let mut file = options.open(&tmp)?;
        file.write_all(contents.as_ref())?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        #[cfg(unix)] if let Some(parent) = path.parent() { std::fs::File::open(parent)?.sync_all()?; }
        Ok(())
    })();
    if result.is_err() { let _ = std::fs::remove_file(tmp); }
    result
}

/// Address classes that must not arrive in an external domain's answers.
pub fn is_internal_address(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            let o = v.octets();
            v.is_private() || v.is_loopback() || v.is_link_local() || v.is_unspecified()
                || v.is_multicast() || v.is_broadcast() || o[0] == 0 || o[0] >= 240
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && (o[2] == 0 || o[2] == 2))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19 || (o[1] == 51 && o[2] == 100)))
                || (o[0] == 203 && o[1] == 0 && o[2] == 113)
        }
        std::net::IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() { return is_internal_address(v4.into()); }
            v.is_loopback() || v.is_unspecified() || v.is_multicast()
                || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80
                || (v.segments()[0] == 0x2001 && v.segments()[1] == 0x0db8)
        }
    }
}

pub fn allowed_dns_client(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => v.is_loopback() || v.is_private() || v.is_link_local() || (v.octets()[0] == 100 && (v.octets()[1] & 0xc0) == 64),
        std::net::IpAddr::V6(v) => v.to_ipv4_mapped().map(|v| allowed_dns_client(v.into())).unwrap_or(v.is_loopback() || (v.segments()[0] & 0xfe00) == 0xfc00 || (v.segments()[0] & 0xffc0) == 0xfe80),
    }
}

#[cfg(test)]
mod security_tests {
    #[test] fn special_addresses() {
        for ip in ["169.254.169.254", "100.100.100.100", "192.0.2.1", "198.18.0.1", "198.51.100.1", "203.0.113.1", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1"] { assert!(super::is_internal_address(ip.parse().unwrap())); }
        assert!(!super::is_internal_address("8.8.8.8".parse().unwrap()));
    }
    #[test] fn escaping_and_canonicalization() {
        assert_eq!(super::canonical_domain("WWW.Example.COM."), "www.example.com");
        assert!(!super::html_escape("<script>'&\"").contains('<'));
    }
}

pub mod dns;

pub mod upstream;
