pub mod paths;
use serde::{Deserialize, Serialize};

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
