use analytics::RelationshipObservation;
use ipnet::IpNet;
use std::net::IpAddr;
use std::sync::{OnceLock, RwLock};

#[derive(Clone, Default)]
pub struct IpMetadata {
    entries: std::sync::Arc<Vec<IpMetadataEntry>>,
}

#[derive(Clone)]
struct IpMetadataEntry {
    network: IpNet,
    asn: String,
    country: String,
    organization: String,
}

impl IpMetadata {
    pub fn load() -> Self {
        let path=std::env::var("AEGIS_IP_METADATA").ok().map(std::path::PathBuf::from)
            .unwrap_or_else(||config::paths::get_data_dir().join("ip-metadata.csv"));
        let Ok(text)=std::fs::read_to_string(&path) else { return Self::default(); };
        let mut entries=Vec::new();
        for (index,line) in text.lines().enumerate() {
            let line=line.trim();
            if line.is_empty()||line.starts_with('#'){continue;}
            let fields:Vec<_>=line.splitn(4,',').map(str::trim).collect();
            if fields.len()!=4 {tracing::warn!("Ignoring malformed IP metadata row {}",index+1);continue;}
            let Ok(network)=fields[0].parse() else {tracing::warn!("Ignoring invalid CIDR on IP metadata row {}",index+1);continue;};
            entries.push(IpMetadataEntry{network,asn:fields[1].into(),country:fields[2].into(),organization:fields[3].into()});
        }
        entries.sort_by_key(|entry|std::cmp::Reverse(entry.network.prefix_len()));
        tracing::info!("Loaded {} local IP metadata ranges",entries.len());
        Self{entries:std::sync::Arc::new(entries)}
    }

    pub fn observations(&self,source_domain:&str,ip:IpAddr)->Vec<RelationshipObservation>{
        let ip_string=ip.to_string();
        let mut out=vec![linked_observation(source_domain,"domain","resolves_to",&ip_string,"ip"),linked_observation(&ip_string,"ip","uses_network",&network_prefix(ip),"network")];
        if let Some(entry)=self.entries.iter().find(|entry|entry.network.contains(&ip)) {
            if !entry.asn.is_empty(){out.push(linked_observation(&ip_string,"ip","announced_by",&format!("{} {}",entry.asn,entry.organization).trim(),"asn"));}
            if !entry.country.is_empty(){out.push(linked_observation(&ip_string,"ip","located_in",&entry.country,"country"));}
        }
        out
    }
}

pub fn observation(relation:&str,target:&str,kind:&str)->RelationshipObservation{
    RelationshipObservation{source:None,source_kind:None,relation:relation.into(),target:target.into(),target_kind:kind.into()}
}

pub fn linked_observation(source:&str,source_kind:&str,relation:&str,target:&str,target_kind:&str)->RelationshipObservation{
    RelationshipObservation{source:Some(source.into()),source_kind:Some(source_kind.into()),relation:relation.into(),target:target.into(),target_kind:target_kind.into()}
}

// ---------------------------------------------------------------------------
// DomainRegistry – file-backed tracker & application lists with built-in defaults
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct DomainRegistry {
    trackers: Vec<(String, String)>,
    applications: Vec<(String, String)>,
}

#[derive(serde::Deserialize)]
struct DomainEntry {
    domain: String,
    company: String,
}

static REGISTRY: OnceLock<RwLock<DomainRegistry>> = OnceLock::new();

fn default_applications() -> Vec<(String, String)> {
    vec![
        ("youtube.com".into(),"YouTube".into()),("googlevideo.com".into(),"YouTube".into()),("netflix.com".into(),"Netflix".into()),("nflxvideo.net".into(),"Netflix".into()),
        ("spotify.com".into(),"Spotify".into()),("discord.com".into(),"Discord".into()),("discordapp.net".into(),"Discord".into()),("reddit.com".into(),"Reddit".into()),
        ("instagram.com".into(),"Instagram".into()),("facebook.com".into(),"Facebook".into()),("fbcdn.net".into(),"Facebook".into()),("whatsapp.net".into(),"WhatsApp".into()),
        ("github.com".into(),"GitHub".into()),("githubusercontent.com".into(),"GitHub".into()),("microsoft.com".into(),"Microsoft".into()),("office.com".into(),"Microsoft 365".into()),
        ("apple.com".into(),"Apple".into()),("icloud.com".into(),"iCloud".into()),("amazon.com".into(),"Amazon".into()),("twitch.tv".into(),"Twitch".into()),
    ]
}

fn default_trackers() -> Vec<(String, String)> {
    vec![
        ("doubleclick.net".into(),"Google".into()),("google-analytics.com".into(),"Google".into()),("googletagmanager.com".into(),"Google".into()),("app-measurement.com".into(),"Google".into()),
        // Only third-party tracking endpoints belong here. `facebook.com` was
        // listed as well, which made a first-party visit to Facebook count as
        // contacting a tracking company and double-counted it against the
        // device's privacy score. `facebook.net` (connect.facebook.net) is the
        // domain that actually serves the tracking pixel.
        ("facebook.net".into(),"Meta".into()),("segment.io".into(),"Twilio Segment".into()),("segment.com".into(),"Twilio Segment".into()),
        ("mixpanel.com".into(),"Mixpanel".into()),("amplitude.com".into(),"Amplitude".into()),("hotjar.com".into(),"Hotjar".into()),("appsflyer.com".into(),"AppsFlyer".into()),
        ("adjust.com".into(),"Adjust".into()),("branch.io".into(),"Branch".into()),("criteo.com".into(),"Criteo".into()),("taboola.com".into(),"Taboola".into()),
    ]
}

fn load_entries_from_file(path: &std::path::Path) -> Option<Vec<(String, String)>> {
    let text = std::fs::read_to_string(path).ok()?;
    let entries: Vec<DomainEntry> = serde_json::from_str(&text).ok()?;
    Some(entries.into_iter().map(|e| (e.domain, e.company)).collect())
}

impl DomainRegistry {
    fn load() -> Self {
        let data_dir = config::paths::get_data_dir();

        let applications = load_entries_from_file(&data_dir.join("applications.json"))
            .unwrap_or_else(|| {
                tracing::debug!("Using built-in default applications list");
                default_applications()
            });

        let trackers = load_entries_from_file(&data_dir.join("trackers.json"))
            .unwrap_or_else(|| {
                tracing::debug!("Using built-in default trackers list");
                default_trackers()
            });

        // A domain classified as both a first-party application and a
        // third-party tracker is counted twice in the privacy score. The
        // application meaning wins, because a user deliberately visiting a
        // site is not the same as that site's pixel appearing elsewhere.
        let mut trackers = trackers;
        let overlap: Vec<String> = trackers
            .iter()
            .filter(|(domain, _)| applications.iter().any(|(app, _)| app == domain))
            .map(|(domain, _)| domain.clone())
            .collect();
        if !overlap.is_empty() {
            tracing::warn!(
                "Ignoring tracker entries that are also applications: {}",
                overlap.join(", ")
            );
            trackers.retain(|(domain, _)| !overlap.contains(domain));
        }

        tracing::info!(
            "DomainRegistry loaded: {} applications, {} trackers",
            applications.len(),
            trackers.len()
        );

        Self { trackers, applications }
    }
}

fn get_registry() -> &'static RwLock<DomainRegistry> {
    REGISTRY.get_or_init(|| RwLock::new(DomainRegistry::load()))
}

/// Reload the domain registry from disk. Falls back to built-in defaults on
/// missing or unparseable files.
#[allow(dead_code)]
pub fn reload() {
    let new = DomainRegistry::load();
    if let Some(lock) = REGISTRY.get() {
        if let Ok(mut guard) = lock.write() {
            *guard = new;
        }
    }
}

/// True when `domain` is `suffix` itself or a subdomain of it.
///
/// Compared without allocating: the previous implementation built a
/// `format!(".{suffix}")` String for every entry of every lookup, and this
/// runs on the DNS hot path for each query.
fn matches_suffix(domain: &str, suffix: &str) -> bool {
    if domain == suffix {
        return true;
    }
    // `domain` must end with `suffix` preceded by a dot, so that
    // "notfacebook.com" never matches the suffix "facebook.com".
    domain.len() > suffix.len()
        && domain.ends_with(suffix)
        && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
}

/// Find the most specific matching entry.
///
/// Longest-suffix wins so that a precise entry beats a broader parent domain
/// regardless of the order entries appear in the file.
fn lookup(entries: &[(String, String)], domain: &str) -> Option<String> {
    entries
        .iter()
        .filter(|(suffix, _)| matches_suffix(domain, suffix))
        .max_by_key(|(suffix, _)| suffix.len())
        .map(|(_, name)| name.clone())
}

pub fn application(domain: &str) -> Option<String> {
    let reg = get_registry().read().ok()?;
    lookup(&reg.applications, domain)
}

pub fn tracking_company(domain: &str) -> Option<String> {
    let reg = get_registry().read().ok()?;
    lookup(&reg.trackers, domain)
}

pub fn contains_identifier(domain:&str)->bool{
    domain.split('.').any(|label|label.len()>=20&&label.bytes().any(|b|b.is_ascii_digit())&&label.bytes().any(|b|b.is_ascii_alphabetic()))
}

fn network_prefix(ip:IpAddr)->String{match ip{
    IpAddr::V4(ip)=>{let o=ip.octets();format!("{}.{}.{}.0/24",o[0],o[1],o[2])},
    IpAddr::V6(ip)=>{let s=ip.segments();format!("{:x}:{:x}:{:x}:{:x}::/64",s[0],s[1],s[2],s[3])},
}}

#[cfg(test)] mod tests{
    use super::*;
    #[test] fn deterministic_classification(){assert_eq!(application("i.ytimg.com"),None);assert_eq!(application("www.youtube.com"),Some("YouTube".into()));assert_eq!(tracking_company("stats.doubleclick.net"),Some("Google".into()));assert!(contains_identifier("abc123def456ghi789jkl.example"));}

    /// Suffix matching must respect label boundaries: a domain that merely
    /// ends with the same characters is a different domain.
    #[test] fn suffix_match_respects_label_boundaries(){
        assert!(matches_suffix("facebook.com","facebook.com"));
        assert!(matches_suffix("www.facebook.com","facebook.com"));
        assert!(!matches_suffix("notfacebook.com","facebook.com"));
        assert!(!matches_suffix("com","facebook.com"));
    }

    /// The most specific entry wins regardless of list order.
    #[test] fn longest_suffix_wins(){
        let entries=vec![
            ("example.com".to_string(),"Broad".to_string()),
            ("cdn.example.com".to_string(),"Specific".to_string()),
        ];
        assert_eq!(lookup(&entries,"cdn.example.com"),Some("Specific".into()));
        assert_eq!(lookup(&entries,"other.example.com"),Some("Broad".into()));
    }

    /// No domain may be both a first-party application and a third-party
    /// tracker, or it is counted twice in the privacy score.
    #[test] fn defaults_do_not_classify_a_domain_twice(){
        let apps=default_applications();
        let overlap:Vec<_>=default_trackers().into_iter()
            .filter(|(domain,_)|apps.iter().any(|(app,_)|app==domain))
            .map(|(domain,_)|domain)
            .collect();
        assert!(overlap.is_empty(),"domains classified as both application and tracker: {overlap:?}");
    }

    #[test] fn network_prefix_groups_by_subnet(){
        assert_eq!(network_prefix("192.168.1.55".parse().unwrap()),"192.168.1.0/24");
        assert_eq!(network_prefix("2001:db8:1:2:3:4:5:6".parse().unwrap()),"2001:db8:1:2::/64");
    }

    /// Short labels and pure-digit labels are not tracking identifiers.
    #[test] fn identifier_detection_needs_mixed_long_label(){
        assert!(!contains_identifier("www.example.com"));
        assert!(!contains_identifier("123456789012345678901234.example"),"digits only is not an identifier");
        assert!(contains_identifier("a1b2c3d4e5f6g7h8i9j0k.example"));
    }
}
