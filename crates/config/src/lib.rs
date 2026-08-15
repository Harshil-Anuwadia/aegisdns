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
