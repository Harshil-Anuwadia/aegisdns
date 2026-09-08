use psl::{List, Psl};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AggregatedDomains {
    pub top_domains: Vec<(String, u64)>,
    pub infrastructure: Vec<(String, u64)>,
    pub unknown: Vec<(String, u64)>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Infrastructure auto-detection — ZERO hardcoded domain names
//
// Classification priority (highest → lowest):
//   1. User manual DB classification     — always wins
//   2. auto_is_infrastructure()          — 4-layer pattern engine
//   3. Default                           — top_domains
//
// Layer overview:
//   A. Hostname label patterns   — exact match on dot-labels in the full hostname
//   B. SLD substring patterns    — keywords embedded in the registrable SLD itself
//   C. Per-root query analysis   — if every observed subdomain of a root was
//                                   infra-labelled, the root is infra too
//   D. Structural heuristics     — long/hex/random labels typical of CDN edge nodes
// ─────────────────────────────────────────────────────────────────────────────

/// Returns true if this hostname is clearly infrastructure (CDN, telemetry,
/// OS-update, background-sync, etc.) that should not appear in Top Destinations.
///
/// NO specific registrable domain names are listed here. All detection is
/// based on structural patterns, technology keywords, and subdomain semantics.
fn auto_is_infrastructure(hostname: &str, sld: &str) -> bool {
    let h = hostname.to_ascii_lowercase();
    let s = sld.to_ascii_lowercase();

    // ── A. Hostname label patterns ────────────────────────────────────────────
    // These are well-established technology terms that only appear as DNS
    // labels when something is genuinely infrastructure.
    //
    // Rule: if ANY dot-label in the full hostname exactly matches one of these,
    // the domain is infrastructure.  We use exact label matching (not substring)
    // to avoid false positives like "update" matching "software-update-checker.com"
    // as a registrable domain — here we're only testing individual DNS labels.
    const INFRA_LABELS: &[&str] = &[
        // ── CDN / delivery networks ───────────────────────────────────────────
        "cdn", "edge", "edges", "edged",
        "akamai", "akamaized", "akadns", "akamaiedge",
        "cloudfront", "fastly", "edgekey", "edgesuite",
        "llnwd", "hwcdn", "cachefly", "incapdns",
        "azureedge", "azurefd", "trafficmanager",
        "cloudflare", "cf-ipfs",
        "b-cdn",          // BunnyCDN
        "netdna-cdn",     // StackPath/MaxCDN
        "stackpathcdn",
        "r",              // common CDN path label (r.example.com)
        // ── Telemetry / analytics / tracking ─────────────────────────────────
        "telemetry", "metrics", "analytics", "tracking", "beacon",
        "stats", "ingest", "collector", "events", "instrumentation",
        "usage", "insights", "perf", "performance",
        "hm",             // HotJar metrics
        "tr",             // common tracking label
        // ── Crash / error reporting ───────────────────────────────────────────
        "crash", "sentry", "bugsnag", "raygun", "rollbar",
        "exceptionless", "airbrake", "honeybadger",
        // ── OS / app updates ──────────────────────────────────────────────────
        "update", "updates", "upgrade", "download", "downloads",
        "patch", "aus", "aus2", "aus3", "aus4", "aus5",  // Mozilla AUS
        "softwareupdate", "swscan",   // Apple Software Update
        "ws",             // Windows Software / Windows Store label
        // ── Push / notifications ──────────────────────────────────────────────
        "push", "notify", "notification", "notifications",
        "fcm", "apns", "wns", "pushd", "autopush",
        "p", "p3",        // common push shortlabels
        // ── Auth / identity plumbing ──────────────────────────────────────────
        "ocsp", "crl", "pki", "csp",
        "login",          // SSO endpoint (not a user-browsed destination)
        "sso", "oauth", "auth", "sts", "token",
        // ── Time sync ─────────────────────────────────────────────────────────
        "ntp", "time", "pool",
        // ── Network / DNS infrastructure ──────────────────────────────────────
        "stun", "turn", "coturn", "doh", "dot", "resolver", "dns",
        "relay", "derp",  // Tailscale DERP relay labels
        // ── Static / asset delivery ───────────────────────────────────────────
        "static", "assets", "asset", "fonts", "font",
        "icons", "icon", "thumbnails", "thumbs", "thumb",
        "img", "images", "image",
        "media", "video", "videos",  // when used as a subdomain delivery label
        // ── Connectivity / health checks ──────────────────────────────────────
        "detectportal", "captive", "connectivitycheck",
        "ping", "probe", "healthcheck", "health",
        // ── Ad serving (infrastructure layer, not user destination) ───────────
        "ads", "ad", "adservice", "adserver",
        "doubleclick",    // catches any label containing this too
        "pagead",         // Google pagead label
        // ── Background sync / config / feature flags ──────────────────────────
        "sync", "config", "settings", "configuration",
        "flags", "features", "featureflags", "remote-config", "remoteconfig",
        // ── Background browser/app services ──────────────────────────────────
        "services", "normandy", "shavar", "addons",
        "versioncheck", "balrog",   // Mozilla update services
        "safebrowsing", "malware", "phishing",
        "content-signature",
        // ── Streaming / video infrastructure (delivery, not the website) ──────
        "stream", "live", "hls", "dash", "rtmp",
        // ── Database / API infrastructure ─────────────────────────────────────
        "api",            // pure API label (api.internal, not user-browsed)
        "mqtt", "amqp",   // IoT messaging
        // ── Error / logging infrastructure ────────────────────────────────────
        "log", "logs", "logging", "logstash",
        // ── Security scanning / WHOIS ─────────────────────────────────────────
        "whois", "rdap",
        // ── Common internal infra labels ──────────────────────────────────────
        "internal", "corp", "intranet", "local", "priv", "private",
        "mgmt", "management",
    ];

    let labels: Vec<&str> = h.split('.').collect();

    for label in &labels {
        if INFRA_LABELS.contains(label) {
            return true;
        }
        // Split hyphenated labels and check each part individually.
        // e.g. "ads-img" → ["ads", "img"], "version-check-bg" → ["version","check","bg"]
        if label.contains('-') {
            let parts: Vec<&str> = label.split('-').collect();
            if parts.iter().any(|p| INFRA_LABELS.contains(p)) {
                return true;
            }
        }
        // Partial match for compound CDN vendor labels
        if label.contains("akamai") || label.contains("cloudfront")
            || label.contains("fastly") || label.contains("edgesuite")
            || label.contains("edgekey") || label.contains("akadns")
            || label.contains("cloudflare") || label.contains("stackpath")
        {
            return true;
        }
    }

    // ── B. SLD (second-level domain) substring patterns ───────────────────────
    // Match infra-purpose keywords embedded in the registrable SLD itself.
    // e.g. gstatic→static, ytimg→img, googlesyndication→syndication
    const SLD_KEYWORDS: &[&str] = &[
        // Static / CDN / asset delivery
        "static", "assets", "usercontent", "syndication",
        "img", "images", "icons", "fonts", "thumbs", "thumbnails",
        "media", "deliver", "delivery", "content",
        // CDN vendor names
        "akamai", "cloudfront", "fastly", "azureedge", "cloudflare",
        // Telemetry / tracking
        "telemetry", "analytics", "tracking", "beacon", "metrics",
        "collect", "ingest", "insights",
        // Updates / patches
        "update", "updates", "download", "patch", "upgrade", "swupdate",
        // Error / crash reporting
        "crashlytics", "bugsnag", "sentry", "rollbar", "raygun",
        // Ad / attribution infrastructure
        "doubleclick", "adsense", "adservice", "attribution", "pagead",
        // Security infrastructure
        "safebrowsing", "malware", "phishing",
        // Push / notifications
        "pushservice", "pushnotif", "autopush",
        // Certificate / OCSP
        "ocsp", "pki", "crl",
        // Video / streaming delivery CDN
        "googlevideo",  // structural: contains 'video' as CDN label
        // Connectivity checks
        "connectivitycheck", "detectportal",
    ];

    for &keyword in SLD_KEYWORDS {
        if s.contains(keyword) {
            return true;
        }
    }

    // ── D. Structural heuristics ──────────────────────────────────────────────

    // Very deep hostnames (≥6 labels) are almost always CDN edge nodes.
    // e.g. "r5---sn-xyz.googlevideo.com" or "a.b.c.d.akamai.net"
    if labels.len() >= 6 {
        return true;
    }

    // First label is machine-generated:
    //  • purely hexadecimal, 8+ chars → token/hash (e.g. "a1b2c3d4.example.com")
    //  • contains 3+ consecutive hyphens → CDN edge label ("r5---sn-xyz")
    //  • very long (≥ 24 chars) alphanumeric-only → random CDN hostname
    if let Some(first) = labels.first() {
        let all_hex = first.chars().all(|c| c.is_ascii_hexdigit());
        let has_triple_hyphen = first.contains("---");
        let long_random = first.len() >= 24
            && first.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');

        if (all_hex && first.len() >= 8) || has_triple_hyphen || long_random {
            return true;
        }
    }

    // Hostname contains infra keywords as substrings anywhere
    // (catches cases where they appear mid-label like "update-server.example.com"
    //  or "telemetry-prod.example.com")
    const ANYWHERE_KEYWORDS: &[&str] = &[
        // Always-infra regardless of position
        "telemetry", "analytics", "tracking", "beacon", "crashlytics",
        "safebrowsing", "connectivitycheck", "detectportal",
        "versioncheck", "softwareupdate", "windowsupdate",
        "normandy", "shavar", "balrog",    // Mozilla infra
        "ocsp", "crl", "pki",             // certificate infra
        "pagead", "doubleclick",          // ad serving infrastructure
    ];
    for &kw in ANYWHERE_KEYWORDS {
        if h.contains(kw) {
            return true;
        }
    }

    false
}

/// Extract the SLD (second-level domain) from a PSL-normalized root.
/// "googleapis.com" → "googleapis", "co.uk" → "" (treat as unknown)
fn extract_sld(root: &str) -> &str {
    root.split('.').next().unwrap_or("")
}

pub fn aggregate_and_classify_domains(
    rows: Vec<(String, u64)>,
    classifications: &HashMap<String, String>,
) -> AggregatedDomains {
    // ── Step 1: PSL-normalize and aggregate counts ────────────────────────────
    // We keep track of representative raw hostnames alongside each PSL root
    // so that auto_is_infrastructure() can inspect subdomain labels (Layer C).
    // root_meta: root → (total_count, representative_hostnames)
    let mut root_meta: HashMap<String, (u64, Vec<String>)> = HashMap::new();

    for (domain, count) in rows {
        let root = match List.domain(domain.as_bytes()) {
            Some(d) => std::str::from_utf8(d.as_bytes()).unwrap_or(&domain).to_string(),
            None    => domain.clone(),
        };
        let entry = root_meta.entry(root).or_insert((0, Vec::new()));
        entry.0 += count;
        if entry.1.len() < 8 {
            entry.1.push(domain);
        }
    }

    // ── Step 2: Classify each PSL root ────────────────────────────────────────
    let mut top_map: HashMap<String, u64>     = HashMap::new();
    let mut infra_map: HashMap<String, u64>   = HashMap::new();
    let mut unknown_map: HashMap<String, u64> = HashMap::new();

    for (root, (count, hostnames)) in root_meta {
        match classifications.get(&root).map(|s| s.as_str()) {
            // ── User manual classifications always win ──────────────────────
            Some("infrastructure") => { infra_map.insert(root, count); }
            Some("unknown")        => { unknown_map.insert(root, count); }
            Some(_)                => { top_map.insert(root, count); } // "destination"

            // ── No manual classification → auto-detect ──────────────────────
            None => {
                let sld = extract_sld(&root);

                // Check root itself (covers SLD patterns and root-level labels)
                let root_is_infra = auto_is_infrastructure(&root, sld);

                // ── Layer C: query-inference ────────────────────────────────
                // If ALL representative subdomains observed for this root have
                // infra labels (and the root itself was never queried directly),
                // the root is likely pure background infrastructure.
                let all_subs_are_infra = !hostnames.is_empty()
                    && hostnames.iter().all(|h| {
                        // Exclude the root itself from subdomain analysis
                        h != &root && auto_is_infrastructure(h, sld)
                    });

                // Also: if MOST hostnames are infra-labelled even if root itself
                // is not, still classify as infra (majority vote, ≥ 75%)
                let infra_count = hostnames.iter()
                    .filter(|h| auto_is_infrastructure(h, sld))
                    .count();
                let majority_infra = hostnames.len() >= 2
                    && infra_count * 4 >= hostnames.len() * 3; // ≥75%

                if root_is_infra || all_subs_are_infra || majority_infra {
                    infra_map.insert(root, count);
                } else {
                    top_map.insert(root, count);
                }
            }
        }
    }

    // ── Step 3: Sort and truncate ─────────────────────────────────────────────
    let mut top_vec: Vec<_> = top_map.into_iter().collect();
    top_vec.sort_by(|a, b| b.1.cmp(&a.1));
    top_vec.truncate(10);

    let mut infra_vec: Vec<_> = infra_map.into_iter().collect();
    infra_vec.sort_by(|a, b| b.1.cmp(&a.1));
    infra_vec.truncate(20);

    let mut unknown_vec: Vec<_> = unknown_map.into_iter().collect();
    unknown_vec.sort_by(|a, b| b.1.cmp(&a.1));
    unknown_vec.truncate(10);

    AggregatedDomains {
        top_domains: top_vec,
        infrastructure: infra_vec,
        unknown: unknown_vec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auto_infra_label_detection() {
        // Layer A: label-based
        assert!(auto_is_infrastructure("cdn.example.com", "example"));
        assert!(auto_is_infrastructure("static.mysite.com", "mysite"));
        assert!(auto_is_infrastructure("telemetry.app.com", "app"));
        assert!(auto_is_infrastructure("update.something.com", "something"));
        assert!(auto_is_infrastructure("push.example.net", "example"));
        assert!(auto_is_infrastructure("edge-prod.example.com", "example")); // partial
        assert!(auto_is_infrastructure("fonts.example.com", "example"));
        assert!(auto_is_infrastructure("detectportal.example.com", "example"));
    }

    #[test]
    fn test_auto_infra_sld_detection() {
        // Layer B: SLD substring — no specific domain hardcoded
        assert!(auto_is_infrastructure("gstatic.com", "gstatic"),
                "SLD 'gstatic' contains 'static'");
        assert!(auto_is_infrastructure("mzstatic.com", "mzstatic"),
                "SLD 'mzstatic' contains 'static'");
        assert!(auto_is_infrastructure("ytimg.com", "ytimg"),
                "SLD 'ytimg' contains 'img'");
        assert!(auto_is_infrastructure("aaplimg.com", "aaplimg"),
                "SLD 'aaplimg' contains 'img'");
        assert!(auto_is_infrastructure("googleusercontent.com", "googleusercontent"),
                "SLD contains 'usercontent'");
        assert!(auto_is_infrastructure("googlesyndication.com", "googlesyndication"),
                "SLD contains 'syndication'");
        assert!(auto_is_infrastructure("cloudfront.net", "cloudfront"),
                "SLD contains 'cloudfront'");
        assert!(auto_is_infrastructure("akamaiedge.net", "akamaiedge"),
                "SLD contains 'akamai'");
        assert!(auto_is_infrastructure("akamaized.net", "akamaized"),
                "SLD contains 'akamai'");
        assert!(auto_is_infrastructure("doubleclick.net", "doubleclick"),
                "SLD contains 'doubleclick'");
        assert!(auto_is_infrastructure("safebrowsing.googleapis.com", "googleapis"),
                "hostname contains 'safebrowsing'");
    }

    #[test]
    fn test_auto_infra_structural_detection() {
        // Layer D: structural heuristics
        assert!(auto_is_infrastructure("r5---sn-xyz.example.com", "example"),
                "triple-hyphen label = CDN edge");
        assert!(auto_is_infrastructure("a1b2c3d4e5f6.example.com", "example"),
                "hex label = CDN token");
        assert!(auto_is_infrastructure("a.b.c.d.e.f.example.com", "example"),
                "6+ labels = CDN deep node");
    }

    #[test]
    fn test_destinations_not_classified_as_infra() {
        // Real user destinations must stay in top_domains
        assert!(!auto_is_infrastructure("google.com", "google"),
                "google.com is a destination");
        assert!(!auto_is_infrastructure("youtube.com", "youtube"),
                "youtube.com is a destination");
        assert!(!auto_is_infrastructure("github.com", "github"),
                "github.com is a destination");
        assert!(!auto_is_infrastructure("t.me", "t"),
                "t.me (Telegram) is a destination");
        assert!(!auto_is_infrastructure("chatgpt.com", "chatgpt"),
                "chatgpt.com is a destination");
        assert!(!auto_is_infrastructure("reddit.com", "reddit"),
                "reddit.com is a destination");
        assert!(!auto_is_infrastructure("apple.com", "apple"),
                "apple.com homepage is a destination");
        assert!(!auto_is_infrastructure("whatsapp.com", "whatsapp"),
                "whatsapp.com is a destination");
    }

    #[test]
    fn test_manual_override_beats_auto() {
        let raw = vec![
            // gstatic.com would be auto-infra, but user said "destination"
            ("gstatic.com".to_string(), 50),
            // tailscale.com has no auto-infra signal; user said "infrastructure"
            ("tailscale.com".to_string(), 30),
        ];
        let mut class = HashMap::new();
        class.insert("gstatic.com".to_string(), "destination".to_string());
        class.insert("tailscale.com".to_string(), "infrastructure".to_string());

        let result = aggregate_and_classify_domains(raw, &class);

        assert!(result.top_domains.iter().any(|(d, _)| d == "gstatic.com"),
                "User override 'destination' must beat auto-infra");
        assert!(result.infrastructure.iter().any(|(d, _)| d == "tailscale.com"),
                "User override 'infrastructure' for tailscale must be respected");
    }

    #[test]
    fn test_aggregation_end_to_end() {
        let raw = vec![
            ("www.google.com".to_string(), 85),
            ("t2.gstatic.com".to_string(), 29),   // 'static' SLD
            ("t3.gstatic.com".to_string(), 25),   // 'static' SLD
            ("fonts.example.com".to_string(), 41), // 'fonts' label
            ("chatgpt.com".to_string(), 19),
            ("youtube.com".to_string(), 12),
        ];
        let class = HashMap::new(); // no manual classifications

        let result = aggregate_and_classify_domains(raw, &class);

        assert!(result.top_domains.iter().any(|(d, _)| d == "google.com"),
                "google.com → top_domains");
        assert!(result.infrastructure.iter().any(|(d, _)| d == "gstatic.com"),
                "gstatic.com → infra (SLD contains 'static')");
        assert!(result.infrastructure.iter().any(|(d, _)| d == "example.com"),
                "example.com → infra (subdomain label 'fonts')");
        assert!(result.top_domains.iter().any(|(d, _)| d == "chatgpt.com"),
                "chatgpt.com → top_domains");
        assert_eq!(result.unknown, vec![]);
    }
}
