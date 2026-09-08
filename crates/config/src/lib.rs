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

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct AegisConfig {
    pub resolver: ResolverConfig,
    pub policy: PolicyConfig,
}

#[derive(Debug, Serialize, Deserialize)]
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

#[derive(Debug, Serialize, Deserialize)]
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
}

/// Load the main config.json from the data directory.
/// Returns None if the file is missing or unparseable; callers should fall back to Default.
pub fn load_main_config() -> Option<AegisConfig> {
    let path = paths::get_data_dir().join("config.json");
    let data = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&data).ok()
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
