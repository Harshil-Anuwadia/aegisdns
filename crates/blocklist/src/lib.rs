use std::collections::HashSet;
use std::time::SystemTime;

#[derive(Debug, Clone)]
pub struct ListMetadata {
    pub name: String,
    pub source_url: String,
    pub last_updated: Option<SystemTime>,
    pub checksum: Option<String>,
    pub enabled: bool,
    pub rule_count: usize,
}

pub struct BlocklistManager {
    lists: Vec<ListMetadata>,
    compiled_domains: HashSet<String>,
    /// Live threat intelligence — refreshed every 30 minutes from abuse.ch / URLhaus.
    realtime_threats: HashSet<String>,
    pub realtime_last_updated: Option<SystemTime>,
    pub realtime_threat_count: usize,
}

impl BlocklistManager {
    pub fn new() -> Self {
        Self {
            lists: vec![
                ListMetadata {
                    name: "StevenBlack Standard (Malware/Adware/Trackers)".into(),
                    source_url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into(),
                    last_updated: None,
                    checksum: None,
                    enabled: true,
                    rule_count: 0,
                },
                ListMetadata {
                    name: "StevenBlack Adult Content (Porn)".into(),
                    source_url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts".into(),
                    last_updated: None,
                    checksum: None,
                    enabled: true,
                    rule_count: 0,
                },
                ListMetadata {
                    name: "AdAway Default Blocklist (Ads)".into(),
                    source_url: "https://adaway.org/hosts.txt".into(),
                    last_updated: None,
                    checksum: None,
                    enabled: true,
                    rule_count: 0,
                },
                ListMetadata {
                    name: "Dan Pollock's Hosts (Ads & Trackers)".into(),
                    source_url: "https://someonewhocares.org/hosts/zero/hosts".into(),
                    last_updated: None,
                    checksum: None,
                    enabled: true,
                    rule_count: 0,
                },
                ListMetadata {
                    name: "StevenBlack FakeNews & Gambling".into(),
                    source_url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling/hosts".into(),
                    last_updated: None,
                    checksum: None,
                    enabled: true,
                    rule_count: 0,
                },
            ],
            compiled_domains: HashSet::new(),
            realtime_threats: HashSet::new(),
            realtime_last_updated: None,
            realtime_threat_count: 0,
        }
    }

    pub fn get_lists(&self) -> Vec<ListMetadata> {
        self.lists.clone()
    }

    pub async fn download_lists(mut lists: Vec<ListMetadata>) -> anyhow::Result<(Vec<ListMetadata>, HashSet<String>)> {
        let mut new_compiled = HashSet::new();
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        for list in &mut lists {
            if !list.enabled { continue; }
            let resp = match client.get(&list.source_url).send().await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!("Failed to download blocklist '{}': {}. Skipping.", list.name, e);
                    continue;
                }
            };
            let text = match resp.text().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::warn!("Failed to read blocklist body '{}': {}. Skipping.", list.name, e);
                    continue;
                }
            };
            let mut count = 0;
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') { continue; }
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                    new_compiled.insert(parts[1].to_string());
                    count += 1;
                }
            }
            list.last_updated = Some(SystemTime::now());
            list.rule_count = count;
            list.checksum = Some("sha256_placeholder".into());
        }
        Ok((lists, new_compiled))
    }

    pub fn apply_update(&mut self, lists: Vec<ListMetadata>, new_compiled: HashSet<String>) {
        self.lists = lists;
        self.compiled_domains = new_compiled;
    }

    /// Fetch live threat intelligence from abuse.ch and URLhaus.
    /// Does not mutate state directly; apply the result with apply_realtime_threats.
    pub async fn fetch_realtime_threats() -> HashSet<String> {
        let feeds = [
            // Feodo Tracker — botnet C2 domains
            "https://feodotracker.abuse.ch/downloads/domainblocklist.txt",
            // URLhaus — malware distribution domains (hosts file format)
            "https://urlhaus.abuse.ch/downloads/hostfile/",
        ];

        let mut new_threats: HashSet<String> = HashSet::new();
        
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        for url in &feeds {
            match client.get(*url).send().await {
                Ok(resp) => {
                    match resp.text().await {
                        Ok(text) => {
                            for line in text.lines() {
                                let line = line.trim();
                                if line.is_empty() || line.starts_with('#') { continue; }
                                // URLhaus uses hosts file format: "0.0.0.0 domain"
                                let parts: Vec<&str> = line.split_whitespace().collect();
                                let domain = if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                                    parts[1]
                                } else if parts.len() == 1 && !parts[0].contains('/') {
                                    // Feodo: plain domain list
                                    parts[0]
                                } else {
                                    continue;
                                };
                                // Basic sanity check — must look like a domain
                                if domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.') {
                                    new_threats.insert(domain.to_lowercase());
                                }
                            }
                        }
                        Err(e) => tracing::warn!("Failed to read realtime threat feed body from {}: {}", url, e),
                    }
                }
                Err(e) => tracing::warn!("Failed to fetch realtime threat feed {}: {}", url, e),
            }
        }

        new_threats
    }

    pub fn apply_realtime_threats(&mut self, new_threats: HashSet<String>) {
        let count = new_threats.len();
        self.realtime_threats = new_threats;
        self.realtime_last_updated = Some(SystemTime::now());
        self.realtime_threat_count = count;
        tracing::info!("Realtime threat feed refreshed: {} active threats", count);
    }

    /// Check if a domain is blocked — checks both the compiled blocklist
    /// and the realtime threat feed. Supports subdomain inheritance.
    pub fn is_blocked(&self, domain: &str) -> bool {
        if self.is_in_set(domain, &self.compiled_domains) { return true; }
        if self.is_in_set(domain, &self.realtime_threats) { return true; }
        false
    }

    /// Check if a domain is a live threat (realtime feed only).
    pub fn is_live_threat(&self, domain: &str) -> bool {
        self.is_in_set(domain, &self.realtime_threats)
    }

    fn is_in_set(&self, domain: &str, set: &HashSet<String>) -> bool {
        // Exact match
        if set.contains(domain) { return true; }
        // Subdomain match: walk up labels
        // e.g. "api.ads.doubleclick.net" checks "ads.doubleclick.net", "doubleclick.net"
        let bytes = domain.as_bytes();
        let mut pos = 0;
        while pos < bytes.len() {
            if bytes[pos] == b'.' {
                let suffix = &domain[pos + 1..];
                if !suffix.is_empty() && set.contains(suffix) {
                    return true;
                }
            }
            pos += 1;
        }
        false
    }

    pub fn enable_list(&mut self, name: &str) -> anyhow::Result<()> {
        if let Some(list) = self.lists.iter_mut().find(|l| l.name == name) {
            list.enabled = true;
            Ok(())
        } else {
            anyhow::bail!("List not found: {}", name)
        }
    }

    pub fn disable_list(&mut self, name: &str) -> anyhow::Result<()> {
        if let Some(list) = self.lists.iter_mut().find(|l| l.name == name) {
            list.enabled = false;
            Ok(())
        } else {
            anyhow::bail!("List not found: {}", name)
        }
    }

    pub fn list_status(&self) -> Vec<&ListMetadata> {
        self.lists.iter().collect()
    }
}
