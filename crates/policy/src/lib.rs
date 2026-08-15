use std::collections::{HashSet, HashMap};
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum BlockReason {
    ExplicitDeny,
    ScheduledBlock,
    Security,
    Malware,
    Phishing,
    Tracker,
    Advertisement,
    Telemetry,
    CategorySpecific(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allowed(String),
    Blocked(BlockReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Profile {
    Strict,
    Balanced,
    Compatibility,
}

/// Action for a schedule rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScheduleAction {
    Block,
    Allow,
}

/// A time-based policy rule. Days are 0=Sun..6=Sat.
/// Times are minutes from midnight (0..1439).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleRule {
    /// Unique identifier.
    pub id: String,
    /// Domain pattern (supports wildcards like *.tiktok.com).
    pub domain: String,
    pub action: ScheduleAction,
    /// Days of week this rule applies (0=Sun, 1=Mon, ..., 6=Sat).
    pub days: Vec<u8>,
    /// Start time as minutes from midnight (e.g. 22*60=1320 for 10pm).
    pub start_minutes: u16,
    /// End time as minutes from midnight.
    pub end_minutes: u16,
    /// If Some, only applies to that device. If None, applies globally.
    pub device_id: Option<String>,
    pub enabled: bool,
    /// Human-readable label for the UI.
    pub label: String,
}

impl ScheduleRule {
    /// Check whether this rule is currently active for a given device.
    pub fn is_active_now(&self, device_id: Option<&str>) -> bool {
        if !self.enabled { return false; }

        // Device scoping
        match (&self.device_id, device_id) {
            (Some(rule_dev), Some(req_dev)) => { if rule_dev != req_dev { return false; } }
            (Some(_), None) => { return false; } // Rule is device-specific, request has no device
            (None, _) => {} // Global rule applies to everyone
        }

        let now = Self::current_time_minutes();
        let today = Self::current_weekday();

        if !self.days.contains(&today) { return false; }

        // Handle overnight ranges (e.g. 22:00 to 06:00)
        if self.start_minutes <= self.end_minutes {
            now >= self.start_minutes && now < self.end_minutes
        } else {
            now >= self.start_minutes || now < self.end_minutes
        }
    }

    fn current_time_minutes() -> u16 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // UTC minutes in the current day
        let minutes_today = (secs % 86400) / 60;
        minutes_today as u16
    }

    fn current_weekday() -> u8 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        // Jan 1 1970 was a Thursday (day 4)
        let days_since_epoch = secs / 86400;
        ((days_since_epoch + 4) % 7) as u8
    }
}

#[derive(Serialize, Deserialize)]
pub struct PolicyEngine {
    pub profile: Profile,
    explicit_allow: HashSet<String>,
    temporary_allow: HashSet<String>,
    explicit_deny: HashSet<String>,
    #[serde(default)]
    pub device_explicit_allow: HashMap<String, HashSet<String>>,
    #[serde(default)]
    pub device_explicit_deny: HashMap<String, HashSet<String>>,
    #[serde(default)]
    pub schedules: Vec<ScheduleRule>,
    #[serde(default)]
    pub safe_search_enabled: bool,
    pub emergency_mode: bool,
}

impl PolicyEngine {
    pub fn save(&self) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(config::paths::get_policy_path(), json)?;
        Ok(())
    }

    pub fn load_or_default() -> Self {
        if let Ok(json) = std::fs::read_to_string(config::paths::get_policy_path()) {
            if let Ok(mut engine) = serde_json::from_str::<Self>(&json) {
                engine.explicit_allow = engine.explicit_allow.into_iter()
                    .map(|d| if d.starts_with("www.") { d[4..].to_string() } else { d })
                    .collect();
                engine.explicit_deny = engine.explicit_deny.into_iter()
                    .map(|d| if d.starts_with("www.") { d[4..].to_string() } else { d })
                    .collect();
                let _ = engine.save();
                return engine;
            }
        }
        Self::new(Profile::Balanced)
    }

    pub fn new(profile: Profile) -> Self {
        Self {
            profile,
            explicit_allow: HashSet::new(),
            temporary_allow: HashSet::new(),
            explicit_deny: HashSet::new(),
            device_explicit_allow: HashMap::new(),
            device_explicit_deny: HashMap::new(),
            schedules: Vec::new(),
            safe_search_enabled: false,
            emergency_mode: false,
        }
    }

    pub fn set_profile(&mut self, profile: Profile) {
        self.profile = profile;
    }

    pub fn allow(&mut self, domain: String) {
        let domain = if domain.starts_with("www.") { domain[4..].to_string() } else { domain };
        self.explicit_deny.remove(&domain);
        self.explicit_allow.insert(domain);
    }

    pub fn deny(&mut self, domain: String) {
        let domain = if domain.starts_with("www.") { domain[4..].to_string() } else { domain };
        self.explicit_allow.remove(&domain);
        self.explicit_deny.insert(domain);
    }

    pub fn remove(&mut self, domain: &str) {
        let domain = if domain.starts_with("www.") { &domain[4..] } else { domain };
        self.explicit_allow.remove(domain);
        self.explicit_deny.remove(domain);
    }

    pub fn allow_device(&mut self, domain: String, device_id: String) {
        let domain = if domain.starts_with("www.") { domain[4..].to_string() } else { domain };
        self.device_explicit_deny.entry(device_id.clone()).or_default().remove(&domain);
        self.device_explicit_allow.entry(device_id).or_default().insert(domain);
    }

    pub fn deny_device(&mut self, domain: String, device_id: String) {
        let domain = if domain.starts_with("www.") { domain[4..].to_string() } else { domain };
        self.device_explicit_allow.entry(device_id.clone()).or_default().remove(&domain);
        self.device_explicit_deny.entry(device_id).or_default().insert(domain);
    }

    pub fn remove_device(&mut self, domain: &str, device_id: &str) {
        let domain = if domain.starts_with("www.") { &domain[4..] } else { domain };
        if let Some(set) = self.device_explicit_allow.get_mut(device_id) { set.remove(domain); }
        if let Some(set) = self.device_explicit_deny.get_mut(device_id) { set.remove(domain); }
    }

    // --- Schedule Management ---

    pub fn add_schedule(&mut self, rule: ScheduleRule) {
        self.schedules.retain(|r| r.id != rule.id);
        self.schedules.push(rule);
    }

    pub fn remove_schedule(&mut self, id: &str) {
        self.schedules.retain(|r| r.id != id);
    }

    pub fn toggle_schedule(&mut self, id: &str, enabled: bool) {
        if let Some(r) = self.schedules.iter_mut().find(|r| r.id == id) {
            r.enabled = enabled;
        }
    }

    // --- Accessors ---

    pub fn get_allowed(&self) -> Vec<String> {
        let mut v: Vec<String> = self.explicit_allow.iter().cloned().collect();
        v.sort();
        v
    }

    pub fn get_denied(&self) -> Vec<String> {
        let mut v: Vec<String> = self.explicit_deny.iter().cloned().collect();
        v.sort();
        v
    }

    // --- Matching ---

    fn matches(domain: &str, set: &HashSet<String>) -> bool {
        config::iter_subdomains(domain).any(|sub| {
            set.contains(sub) || set.contains(&format!("*.{}", sub))
        })
    }

    fn matches_pattern(domain: &str, pattern: &str) -> bool {
        let pattern = if pattern.starts_with("www.") { &pattern[4..] } else { pattern };
        let pattern_base = if pattern.starts_with("*.") { &pattern[2..] } else { pattern };
        config::iter_subdomains(domain).any(|sub| sub == pattern_base)
    }

    fn is_typosquatting(domain: &str) -> bool {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() < 2 { return false; }
        let base = format!("{}.{}", parts[parts.len()-2], parts[parts.len()-1]);

        let high_value_domains = [
            "chase.com", "bankofamerica.com", "wellsfargo.com", "citigroup.com", "capitalone.com",
            "usbank.com", "pnc.com", "barclays.com", "hsbc.com", "santander.com", "americanexpress.com", "discover.com",
            "paypal.com", "stripe.com", "square.com", "venmo.com", "cash.app", "wise.com", "revolut.com", "payoneer.com",
            "binance.com", "coinbase.com", "kraken.com", "gemini.com", "kucoin.com", "huobi.com", "bitfinex.com", "ledger.com", "trezor.io",
            "google.com", "apple.com", "microsoft.com", "amazon.com", "github.com", "dropbox.com", "adobe.com",
            "salesforce.com", "slack.com", "zoom.us", "cloudflare.com",
            "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "whatsapp.com", "telegram.org",
            "discord.com", "tiktok.com", "snapchat.com", "pinterest.com",
            "yahoo.com", "outlook.com", "gmail.com", "protonmail.com", "aol.com", "icloud.com",
            "ebay.com", "walmart.com", "target.com", "bestbuy.com", "homedepot.com", "costco.com", "shopify.com", "etsy.com",
            "fedex.com", "ups.com", "dhl.com", "usps.com",
            "irs.gov", "gov.uk", "ssa.gov", "medicare.gov",
            "netflix.com", "spotify.com", "hulu.com", "disneyplus.com", "twitch.tv", "steampowered.com", "epicgames.com",
        ];

        for hv in high_value_domains.iter() {
            if base == *hv { continue; }
            let len_a = base.chars().count();
            let len_b = hv.chars().count();
            if (len_a as i32 - len_b as i32).abs() > 1 { continue; }
            let mut matrix = vec![vec![0; len_b + 1]; len_a + 1];
            for i in 0..=len_a { matrix[i][0] = i; }
            for j in 0..=len_b { matrix[0][j] = j; }
            for (i, ca) in base.chars().enumerate() {
                for (j, cb) in hv.chars().enumerate() {
                    let cost = if ca == cb { 0 } else { 1 };
                    matrix[i + 1][j + 1] = (matrix[i][j + 1] + 1)
                        .min(matrix[i + 1][j] + 1)
                        .min(matrix[i][j] + cost);
                }
            }
            if matrix[len_a][len_b] == 1 { return true; }
        }
        false
    }

    fn is_homograph_attack(domain: &str) -> bool {
        domain.contains("xn--")
    }

    pub fn evaluate(&self, domain: &str, device_id: Option<&str>) -> PolicyDecision {
        if self.emergency_mode {
            return PolicyDecision::Allowed("Emergency mode bypass".into());
        }
        let base_domain = if domain.starts_with("www.") { &domain[4..] } else { domain };

        // 1. Time-based schedule rules (highest priority)
        for schedule in &self.schedules {
            if schedule.is_active_now(device_id) {
                if Self::matches_pattern(domain, &schedule.domain) || Self::matches_pattern(base_domain, &schedule.domain) {
                    return match schedule.action {
                        ScheduleAction::Block => PolicyDecision::Blocked(BlockReason::ScheduledBlock),
                        ScheduleAction::Allow => PolicyDecision::Allowed(format!("Schedule: {}", schedule.label)),
                    };
                }
            }
        }

        // 1. Device-specific Explicit Allow
        if let Some(did) = device_id {
            if let Some(set) = self.device_explicit_allow.get(did) {
                if Self::matches(domain, set) || Self::matches(base_domain, set) {
                    return PolicyDecision::Allowed("Explicit device allow".into());
                }
            }
        }

        // 2. Global Explicit Allow
        if Self::matches(domain, &self.explicit_allow) || Self::matches(base_domain, &self.explicit_allow) {
            return PolicyDecision::Allowed("Explicit user allow".into());
        }

        // 3. Temporary allow
        if Self::matches(domain, &self.temporary_allow) || Self::matches(base_domain, &self.temporary_allow) {
            return PolicyDecision::Allowed("Temporary allow".into());
        }

        // 4. Device-specific Explicit Deny
        if let Some(did) = device_id {
            if let Some(set) = self.device_explicit_deny.get(did) {
                if Self::matches(domain, set) || Self::matches(base_domain, set) {
                    return PolicyDecision::Blocked(BlockReason::ExplicitDeny);
                }
            }
        }

        // 5. Global Explicit Deny
        if Self::matches(domain, &self.explicit_deny) || Self::matches(base_domain, &self.explicit_deny) {
            return PolicyDecision::Blocked(BlockReason::ExplicitDeny);
        }



        // 7. Typosquatting Defense
        if Self::is_typosquatting(domain) {
            return PolicyDecision::Blocked(BlockReason::Phishing);
        }

        // 8. IDN Homograph Attack Defense
        if Self::is_homograph_attack(domain) {
            return PolicyDecision::Blocked(BlockReason::Phishing);
        }

        PolicyDecision::Allowed("Normal resolution".into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_precedence() {
        let mut engine = PolicyEngine::new(Profile::Balanced);
        engine.deny("example.com".into());
        assert_eq!(engine.evaluate("example.com", None), PolicyDecision::Blocked(BlockReason::ExplicitDeny));
        engine.allow("example.com".into());
        assert_eq!(engine.evaluate("example.com", None), PolicyDecision::Allowed("Explicit user allow".into()));
    }

    #[test]
    fn test_wildcard() {
        let mut engine = PolicyEngine::new(Profile::Balanced);
        engine.deny("*.bad.com".into());
        assert_eq!(engine.evaluate("ads.bad.com", None), PolicyDecision::Blocked(BlockReason::ExplicitDeny));
        assert_eq!(engine.evaluate("bad.com", None), PolicyDecision::Blocked(BlockReason::ExplicitDeny));
        assert_eq!(engine.evaluate("notbad.com", None), PolicyDecision::Allowed("Normal resolution".into()));
    }

    #[test]
    fn test_schedule_block() {
        let mut engine = PolicyEngine::new(Profile::Balanced);
        // Create a schedule that blocks all day every day (0:00 to 23:59)
        engine.add_schedule(ScheduleRule {
            id: "test-1".into(),
            domain: "tiktok.com".into(),
            action: ScheduleAction::Block,
            days: vec![0, 1, 2, 3, 4, 5, 6], // all days
            start_minutes: 0,
            end_minutes: 1439,
            device_id: None,
            enabled: true,
            label: "Block TikTok always".into(),
        });
        assert_eq!(engine.evaluate("tiktok.com", None), PolicyDecision::Blocked(BlockReason::ScheduledBlock));
        assert_eq!(engine.evaluate("app.tiktok.com", None), PolicyDecision::Blocked(BlockReason::ScheduledBlock));
    }
}
