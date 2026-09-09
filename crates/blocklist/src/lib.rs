use serde::{Deserialize, Serialize};
use std::{collections::{HashMap, HashSet}, time::SystemTime};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ListMetadata {
    pub name: String,
    pub source_url: String,
    pub last_updated: Option<SystemTime>,
    pub checksum: Option<String>,
    pub enabled: bool,
    pub rule_count: usize,
}

#[derive(Serialize,Deserialize,Default)]
struct Snapshot { lists: Vec<ListMetadata>, domains: HashSet<String>, #[serde(default)] exceptions: HashSet<String>, #[serde(default)] sources: HashMap<String,RuleSet> }
#[derive(Serialize,Deserialize,Clone)]
struct RuleSet { blocked:HashSet<String>, allowed:HashSet<String> }

pub struct BlocklistManager { pub lists:Vec<ListMetadata>, pub compiled_domains:HashSet<String>, pub compiled_exceptions:HashSet<String> }

// Serializes UI mutations and refresh publication. Readers never wait for downloads.
pub static UPDATE_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

impl Default for BlocklistManager { fn default() -> Self { Self::new() } }
impl BlocklistManager {
    pub fn new() -> Self {
        let dir = config::paths::get_data_dir();
        if let Ok(bytes) = std::fs::read(dir.join("blocklist-snapshot.json")) {
            match serde_json::from_slice::<Snapshot>(&bytes) {
                Ok(s) => return Self{lists:s.lists, compiled_domains:s.domains,compiled_exceptions:s.exceptions},
                Err(e) => tracing::error!("Invalid blocklist snapshot, trying legacy files: {}",e),
            }
        }
        let lists = std::fs::read(dir.join("blocklists.json")).ok().and_then(|v|serde_json::from_slice(&v).ok()).unwrap_or_default();
        let compiled_domains = std::fs::read_to_string(dir.join("compiled_domains.txt")).map(|s|s.lines().map(config::canonical_domain).filter(|d|config::valid_domain(d)).collect()).unwrap_or_default();
        Self{lists,compiled_domains,compiled_exceptions:HashSet::new()}
    }
    pub fn get_lists(&self) -> Vec<ListMetadata> { self.lists.clone() }
    pub fn apply_update(&mut self, lists:Vec<ListMetadata>, domains:HashSet<String>, exceptions:HashSet<String>) { self.lists=lists; self.compiled_domains=domains; self.compiled_exceptions=exceptions; }
    pub fn is_blocked(&self, domain:&str) -> bool {
        let domain = config::canonical_domain(domain);
        if config::iter_subdomains(&domain).any(|d|self.compiled_exceptions.contains(d)) { return false; }
        let blocked=config::iter_subdomains(&domain).any(|d|self.compiled_domains.contains(d));
        blocked
    }
    pub fn enable_list(&mut self,name:&str) -> anyhow::Result<()> { self.set_enabled(name,true) }
    pub fn disable_list(&mut self,name:&str) -> anyhow::Result<()> { self.set_enabled(name,false) }
    fn set_enabled(&mut self,name:&str,enabled:bool) -> anyhow::Result<()> {
        let l = self.lists.iter_mut().find(|l|l.name==name).ok_or_else(||anyhow::anyhow!("List not found"))?;
        l.enabled=enabled; Ok(())
    }
    pub fn list_status(&self)->Vec<&ListMetadata> {self.lists.iter().collect()}

    pub async fn download_lists(mut lists:Vec<ListMetadata>) -> anyhow::Result<(Vec<ListMetadata>,HashSet<String>,HashSet<String>)> {
        let dir = config::paths::get_data_dir();
        let old = std::fs::read(dir.join("blocklist-snapshot.json")).ok().and_then(|b|serde_json::from_slice::<Snapshot>(&b).ok()).unwrap_or_default();
        let mut sources = HashMap::new();
        let mut compiled = HashSet::new();
        let mut exceptions = HashSet::new();
        let local_dir = dir.join("blocklists");
        std::fs::create_dir_all(&local_dir)?;
        for entry in std::fs::read_dir(&local_dir)? {
            let entry = entry?;
            // No symlinks: list metadata cannot read outside the configured data directory.
            if !entry.file_type()?.is_file() || entry.path().extension().and_then(|s|s.to_str()) != Some("txt") {continue;}
            let name=entry.file_name().to_string_lossy().to_string();
            let url=format!("file://{}",entry.path().display());
            if !lists.iter().any(|l|l.source_url==url) {
                lists.push(ListMetadata{name,source_url:url,last_updated:None,checksum:None,enabled:true,rule_count:0});
            }
        }
        for list in &mut lists {
            if !list.enabled {continue;}
            let downloaded = if let Some(file)=list.source_url.strip_prefix("file://") {
                let path=std::path::Path::new(file);
                // Existing metadata must point to an actual immediate child of the local folder.
                if path.parent()!=Some(local_dir.as_path()) || std::fs::symlink_metadata(path).map(|m|!m.file_type().is_file()).unwrap_or(true) {
                    Err(anyhow::anyhow!("Local list missing or unsafe: {}",list.name))
                } else {
                    match tokio::fs::metadata(path).await {
                        Ok(meta) if meta.len() <= 64*1024*1024 => tokio::fs::read_to_string(path).await.map_err(Into::into),
                        _ => Err(anyhow::anyhow!("Local list exceeds 64 MiB or cannot be read")),
                    }
                }
            } else { fetch_list(&list.source_url).await };
            let rules = match downloaded {
                Ok(text) => {
                    let (rules, allows)=tokio::task::spawn_blocking(move ||parse_rules(&text)).await?;
                    if rules.is_empty() { // Empty/error documents cannot silently erase a working source.
                        match old.sources.get(&list.source_url) {
                            Some(previous) => { tracing::warn!("Empty list {}; keeping previous rules",list.name); previous.clone() }
                            None => anyhow::bail!("No usable rules in {}",list.name),
                        }
                    } else {
                        list.last_updated=Some(SystemTime::now());
                        RuleSet{blocked:rules,allowed:allows}
                    }
                }
                Err(e) => match old.sources.get(&list.source_url) {
                    Some(previous) => { tracing::warn!("List {} failed: {}; keeping previous rules",list.name,e); previous.clone() }
                    None => return Err(e.context(format!("No last-known-good rules for {}",list.name))),
                }
            };
            list.rule_count=rules.blocked.len(); list.checksum=None;
            compiled.extend(rules.blocked.iter().cloned()); exceptions.extend(rules.allowed.iter().cloned()); sources.insert(list.source_url.clone(),rules);
        }
        // DNS exceptions are applied to their matching blocked suffixes during compilation.
        compiled.retain(|domain|!config::iter_subdomains(domain).any(|suffix|exceptions.contains(suffix)));
        let snapshot=Snapshot{lists:lists.clone(),domains:compiled.clone(),exceptions:exceptions.clone(),sources};
        let path=dir.join("blocklist-snapshot.json");
        tokio::task::spawn_blocking(move ||config::atomic_write(path,serde_json::to_vec(&snapshot)?)).await??;
        Ok((lists,compiled,exceptions))
    }
}

/// Parse only DNS-representable rules. Never reinterpret cosmetic or conditional rules as global blocks.
fn parse_rules(text:&str)->(HashSet<String>,HashSet<String>) {
    let mut blocked=HashSet::new(); let mut allowed=HashSet::new();
    for raw in text.lines() {
        let line=raw.trim();
        if line.is_empty() || line.starts_with(['#','!','[','<']) || line.contains("##") || line.contains("#@#") || line.contains("#?#") {continue;}
        let line=line.split(" #").next().unwrap_or(line).trim();
        let parts:Vec<_>=line.split_whitespace().collect();
        if parts.len()>=2 && matches!(parts[0],"0.0.0.0"|"127.0.0.1"|"::") {
            for part in &parts[1..] { let d=config::canonical_domain(part); if d!="localhost" && d.contains('.') && config::valid_domain(&d) {blocked.insert(d);} }
            continue;
        }
        if parts.len()!=1 || line.contains('$') {continue;}
        let (exception,line)=if let Some(l)=line.strip_prefix("@@") {(true,l)} else {(false,line)};
        let line=line.strip_prefix("||").unwrap_or(line).trim_end_matches('^').trim_start_matches('.');
        let d=config::canonical_domain(line);
        if d.contains('.') && config::valid_domain(&d) && !d.contains('*') {
            if exception {allowed.insert(d);} else {blocked.insert(d);}
        }
    }
    (blocked,allowed)
}

async fn fetch_list(source:&str)->anyhow::Result<String> {
    let url=reqwest::Url::parse(source)?;
    anyhow::ensure!(url.scheme()=="https" && url.username().is_empty() && url.password().is_none(),"Blocklists require HTTPS without embedded credentials");
    let host=url.host_str().ok_or_else(||anyhow::anyhow!("Missing host"))?;
    let port=url.port_or_known_default().unwrap_or(443);
    let addrs:Vec<_>=tokio::time::timeout(std::time::Duration::from_secs(10),tokio::net::lookup_host((host,port))).await??.collect();
    anyhow::ensure!(!addrs.is_empty() && addrs.iter().all(|a|!config::is_internal_address(a.ip())),"Blocklist resolves to an internal/invalid address");
    // Pin checked addresses. Redirects are rejected so a public URL cannot redirect into the LAN.
    let client=reqwest::Client::builder().no_proxy().resolve_to_addrs(host,&addrs).redirect(reqwest::redirect::Policy::none()).timeout(std::time::Duration::from_secs(60)).build()?;
    let mut response=client.get(url).send().await?.error_for_status()?;
    anyhow::ensure!(response.status().is_success(),"Blocklist redirect rejected");
    anyhow::ensure!(response.content_length().unwrap_or(0)<=64*1024*1024,"Blocklist too large");
    let mut bytes=Vec::new();
    while let Some(chunk)=response.chunk().await? {
        anyhow::ensure!(bytes.len()+chunk.len()<=64*1024*1024,"Blocklist too large"); bytes.extend_from_slice(&chunk);
    }
    Ok(String::from_utf8(bytes)?)
}

#[cfg(test)] mod tests {
    use super::*;
    #[test] fn parser_handles_hosts_and_rejects_conditional_cosmetic_rules() {
        let (rules,allows)=parse_rules("0.0.0.0 Ads.Example.com second.example.com\n||tracker.example^\n@@||allowed.example^\nexample.com##.ad\n||conditional.example^$client=phone\n<html>error</html>");
        assert!(rules.contains("ads.example.com")); assert!(rules.contains("second.example.com")); assert!(rules.contains("tracker.example"));
        assert!(!rules.contains("example.com")); assert!(!rules.contains("conditional.example")); assert!(allows.contains("allowed.example"));
    }
    #[test] fn case_insensitive_lookup() {
        let m=BlocklistManager{lists:vec![],compiled_domains:HashSet::from(["example.com".into()]),compiled_exceptions:HashSet::from(["allowed.example.com".into()])};
        assert!(m.is_blocked("ADS.EXAMPLE.COM."));assert!(!m.is_blocked("allowed.example.com"));
    }
}
