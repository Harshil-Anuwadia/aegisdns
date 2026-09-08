use serde::{Deserialize, Serialize};
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UpstreamDnsConfig {
    pub enabled: bool,
    /// always = forwarding only; fallback = forward first, recurse if forwarding fails.
    pub mode: String,
    /// IP:port or tls://IP:853#certificate-hostname. No hostname bootstrap through DNS itself.
    pub resolvers: Vec<String>,
}
impl Default for UpstreamDnsConfig {
    fn default() -> Self { Self { enabled:false, mode:"fallback".into(), resolvers:vec!["9.9.9.9:53".into()] } }
}
impl UpstreamDnsConfig {
    pub fn load() -> anyhow::Result<Self> {
        let path = crate::paths::get_data_dir().join("upstream.json");
        match std::fs::read(path) {
            Ok(bytes) => { let c: Self = serde_json::from_slice(&bytes)?; c.validate()?; Ok(c) },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()), Err(e) => Err(e.into()),
        }
    }
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(matches!(self.mode.as_str(), "always" | "fallback"), "Unknown upstream mode");
        anyhow::ensure!(!self.enabled || !self.resolvers.is_empty(), "Enabled forwarding needs at least one resolver");
        anyhow::ensure!(self.resolvers.len() <= 8, "At most eight resolvers are supported");
        let mut transport = None;
        for endpoint in &self.resolvers {
            let tls = endpoint.starts_with("tls://");
            anyhow::ensure!(!endpoint.starts_with("http"), "DoH forwarding is no longer accepted: use tls://IP:853#certificate-hostname to keep DNSSEC validation inside Unbound");
            if let Some(previous) = transport { anyhow::ensure!(previous == tls, "Do not mix plain DNS and TLS in one forwarding group"); }
            transport = Some(tls);
            let value = endpoint.strip_prefix("tls://").unwrap_or(endpoint);
            let (address, name) = value.split_once('#').unwrap_or((value, ""));
            let addr: std::net::SocketAddr = address.parse().map_err(|_| anyhow::anyhow!("Resolver must use a literal IP and port"))?;
            anyhow::ensure!(addr.port() > 0 && !crate::is_internal_address(addr.ip()), "Resolver must have a public IP and nonzero port; local addresses could loop back into AegisDNS");
            anyhow::ensure!(if tls { crate::valid_domain(name) && !name.contains('*') } else { name.is_empty() }, "TLS requires a certificate hostname after #");
        }
        Ok(())
    }
    pub fn unbound_config(&self) -> anyhow::Result<String> {
        self.validate()?;
        if !self.enabled { return Ok(String::new()); }
        let tls = self.resolvers[0].starts_with("tls://");
        let mut s = format!("\nforward-zone:\n    name: \".\"\n    forward-first: {}\n    forward-tls-upstream: {}\n", if self.mode == "fallback" { "yes" } else { "no" }, if tls { "yes" } else { "no" });
        for endpoint in &self.resolvers {
            let value = endpoint.strip_prefix("tls://").unwrap_or(endpoint);
            let (addr, name) = value.split_once('#').unwrap_or((value, ""));
            let addr: std::net::SocketAddr = addr.parse()?;
            s.push_str(&format!("    forward-addr: {}@{}{}\n",addr.ip(),addr.port(), if name.is_empty() { String::new() } else { format!("#{name}") }));
        }
        Ok(s)
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn validation_and_render() {
        let mut c = UpstreamDnsConfig {enabled:true, mode:"always".into(), resolvers:vec!["tls://9.9.9.9:853#dns.quad9.net".into()]};
        assert!(c.unbound_config().unwrap().contains("forward-tls-upstream: yes"));
        c.resolvers = vec!["127.0.0.1:53".into()]; assert!(c.validate().is_err());
        c.resolvers = vec!["https://dns.example/dns-query".into()]; assert!(c.validate().is_err());
        c.resolvers = vec![]; assert!(c.validate().is_err());
    }
}
