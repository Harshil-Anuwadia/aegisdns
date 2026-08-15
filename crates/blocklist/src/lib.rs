use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListMetadata {
    pub name: String,
    pub source_url: String,
    pub last_updated: Option<SystemTime>,
    pub checksum: Option<String>,
    pub enabled: bool,
    pub rule_count: usize,
}

pub struct BlocklistManager {
    pub lists: Vec<ListMetadata>, // Making lists pub so web.rs can read it easily or provide an accessor. Actually, get_lists() already returns a clone.
    pub compiled_domains: HashSet<String>,
    /// Live threat intelligence — refreshed every 30 minutes from abuse.ch / URLhaus.
    pub realtime_threats: HashSet<String>,
    pub realtime_last_updated: Option<SystemTime>,
    pub realtime_threat_count: usize,
}

impl BlocklistManager {
    pub fn new() -> Self {
        let mut lists = vec![
            ListMetadata {
                name: "StevenBlack Standard (Malware/Adware/Trackers)".into(),
                source_url: "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts".into(),
                last_updated: None,
                checksum: None,
                enabled: true,
                rule_count: 0,
            },

            ListMetadata {
                name: "1Hosts (Xtra)".into(),
                source_url: "https://o0.pages.dev/Xtra/domains.txt".into(),
                last_updated: None,
                checksum: None,
                enabled: true,
                rule_count: 0,
            },
            ListMetadata {
                name: "AdGuard DNS Filter".into(),
                source_url: "https://adguardteam.github.io/HostlistsRegistry/assets/filter_15.txt".into(),
                last_updated: None,
                checksum: None,
                enabled: true,
                rule_count: 0,
            },
            ListMetadata {
                name: "Windows SpyBlocker (Aggressive OS Telemetry)".into(),
                source_url: "https://raw.githubusercontent.com/crazy-max/WindowsSpyBlocker/master/data/hosts/spy.txt".into(),
                last_updated: None,
                checksum: None,
                enabled: true,
                rule_count: 0,
            },

            ListMetadata {
                name: "Hagezi Apple & Amazon OS Trackers".into(),
                source_url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.apple.txt".into(),
                last_updated: None,
                checksum: None,
                enabled: true, 
                rule_count: 0,
            },
            ListMetadata {
                name: "Hagezi Windows & Office Native Telemetry".into(),
                source_url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/native.winoffice.txt".into(),
                last_updated: None,
                checksum: None,
                enabled: true, 
                rule_count: 0,
            },
            ListMetadata {
                name: "Xiaomi Aggressive Telemetry".into(),
                source_url: "https://raw.githubusercontent.com/kevle1/Xiaomi-Telemetry-Blocklist/master/xiaomiblock.txt".into(),
                last_updated: None,
                checksum: None,
                enabled: true, 
                rule_count: 0,
            },
            ListMetadata {
                name: "Perflyst SmartTV & Appliance Blocklist".into(),
                source_url: "https://raw.githubusercontent.com/Perflyst/PiHoleBlocklist/master/SmartTV.txt".into(),
                last_updated: None,
                checksum: None,
                enabled: true, 
                rule_count: 0,
            },
        ];

        let config_dir = config::paths::get_data_dir();
        let lists_path = config_dir.join("blocklists.json");

        if lists_path.exists() {
            if let Ok(contents) = std::fs::read_to_string(&lists_path) {
                if let Ok(saved_lists) = serde_json::from_str::<Vec<ListMetadata>>(&contents) {
                    lists = saved_lists;
                }
            }
        } else {
            let _ = std::fs::create_dir_all(&config_dir);
            if let Ok(json) = serde_json::to_string_pretty(&lists) {
                let _ = std::fs::write(&lists_path, json);
            }
        }

        let mut compiled_domains = HashSet::new();
        let compiled_path = config_dir.join("compiled_domains.txt");
        if compiled_path.exists() {
            if let Ok(file) = std::fs::File::open(&compiled_path) {
                use std::io::BufRead;
                let reader = std::io::BufReader::new(file);
                for line in reader.lines() {
                    if let Ok(domain) = line {
                        if !domain.is_empty() {
                            compiled_domains.insert(domain);
                        }
                    }
                }
            }
        }

        Self {
            lists,
            compiled_domains,
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
            .timeout(std::time::Duration::from_secs(180)) // Increased from 60s for massive lists like OISD Big
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 AegisDNS/1.0")
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
            let (returned_compiled, count) = tokio::task::spawn_blocking(move || {
                let mut count = 0;
                for line in text.lines() {
                    let mut line = line.trim();
                    if line.is_empty() || line.starts_with('#') || line.starts_with('!') || line.starts_with('[') { continue; }
                    // Strip inline comments
                    if let Some(idx) = line.find('#') {
                        line = line[..idx].trim();
                    }
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 2 && (parts[0] == "0.0.0.0" || parts[0] == "127.0.0.1") {
                        new_compiled.insert(parts[1].to_string());
                        count += 1;
                    } else if parts.len() == 1 && !line.contains('/') {
                        let mut domain = line;
                        // Handle Adblock formats
                        if domain.starts_with("||") {
                            domain = &domain[2..];
                        }
                        // Strip anything after ^ or $
                        if let Some(idx) = domain.find('^') {
                            domain = &domain[..idx];
                        }
                        if let Some(idx) = domain.find('$') {
                            domain = &domain[..idx];
                        }
                        if domain.contains('.') {
                            new_compiled.insert(domain.to_string());
                            count += 1;
                        }
                    }
                }
                (new_compiled, count)
            }).await.unwrap();
            new_compiled = returned_compiled;
            list.last_updated = Some(SystemTime::now());
            list.rule_count = count;
            list.checksum = Some("sha256_placeholder".into());
        }
        let config_dir = config::paths::get_data_dir();
        let compiled_path = config_dir.join("compiled_domains.txt");
        if let Ok(file) = std::fs::File::create(&compiled_path) {
            use std::io::Write;
            let mut writer = std::io::BufWriter::new(file);
            for d in &new_compiled {
                let _ = writeln!(writer, "{}", d);
            }
        }
        let lists_path = config_dir.join("blocklists.json");
        if let Ok(json) = serde_json::to_string_pretty(&lists) {
            let _ = std::fs::write(&lists_path, json);
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
            .timeout(std::time::Duration::from_secs(60))
            .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 AegisDNS/1.0")
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());

        for url in &feeds {
            match client.get(*url).send().await {
                Ok(resp) => {
                    match resp.text().await {
                        Ok(text) => {
                            new_threats = tokio::task::spawn_blocking(move || {
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
                                new_threats
                            }).await.unwrap();
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
        config::iter_subdomains(domain).any(|subdomain| set.contains(subdomain))
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
