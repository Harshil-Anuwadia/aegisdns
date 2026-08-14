#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FallbackMode {
    Once,
    Session,
    Permanent,
}

pub struct FallbackRule {
    pub domain: String,
    pub mode: FallbackMode,
}

pub struct FallbackEngine {
    rules: Vec<FallbackRule>,
}

impl FallbackEngine {
    pub fn new() -> Self {
        Self { rules: vec![] }
    }

    pub fn add_fallback(&mut self, domain: String, mode: FallbackMode) {
        self.rules.push(FallbackRule { domain, mode });
    }

    pub fn check_fallback(&self, domain: &str) -> Option<&FallbackMode> {
        self.rules.iter().find(|r| r.domain == domain).map(|r| &r.mode)
    }

    pub fn generate_privacy_warning(domain: &str) -> String {
        format!(
            "PRIVACY WARNING: Fallback enabled for '{}'.\n\
             This domain is being resolved using the configured fallback resolver.\n\
             Privacy impact:\n\
             Your fallback resolver can observe this DNS query.\n\
             AegisDNS remains active for all other domains.",
            domain
        )
    }
}
