use serde::Serialize;

/// A scored risk assessment for a domain.
#[derive(Debug, Clone, Serialize)]
pub struct RiskScore {
    /// Overall risk score from 0 (safe) to 100 (highly suspicious).
    pub score: u8,
    /// Human-readable reasons that contributed to the score.
    pub factors: Vec<String>,
    /// Classification derived from score.
    pub level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum RiskLevel {
    Safe,      // 0-29
    Low,       // 30-49
    Medium,    // 50-69
    High,      // 70-84
    Critical,  // 85-100
}

/// High-risk TLDs frequently used for phishing, malware, and spam.
const HIGH_RISK_TLDS: &[&str] = &[
    "tk", "ml", "ga", "cf", "gq",  // Free TLDs heavily abused
    "pw", "cc", "xyz", "top", "click",
    "loan", "win", "download", "stream",
    "racing", "review", "science", "party",
    "bid", "trade", "webcam", "accountant",
    "faith", "date", "men", "work",
];

/// Keywords commonly found in phishing and social engineering domains.
const SUSPICIOUS_KEYWORDS: &[&str] = &[
    "free", "win", "prize", "lucky", "gift", "bonus",
    "bank", "secure", "login", "signin", "account",
    "verify", "update", "confirm", "validate", "check",
    "password", "credential", "wallet", "crypto", "invest",
    "paypal", "amazon", "apple", "microsoft", "google",
    "netflix", "facebook", "instagram", "discord", "steam",
    "support", "helpdesk", "service", "official", "alert",
    "urgent", "warning", "suspended", "limited", "recover",
];

/// Compute the Shannon entropy of a string.
/// High entropy (>3.5) on a short string suggests a randomly generated (DGA) domain.
fn shannon_entropy(s: &str) -> f64 {
    if s.is_empty() { return 0.0; }
    let mut freq = [0u32; 256];
    let len = s.len() as f64;
    for b in s.bytes() {
        freq[b as usize] += 1;
    }
    freq.iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

const PROTECTED_BRANDS: &[&str] = &[
    "google", "youtube", "facebook", "instagram", "twitter", "apple",
    "microsoft", "amazon", "netflix", "paypal", "steam", "discord",
    "linkedin", "reddit", "whatsapp", "telegram", "binance", "coinbase",
    "chase", "wellsfargo", "bankofamerica", "citibank", "hdfc", "icici",
    "sbi", "axis",
];

/// Names that sit one ordinary edit from a protected brand but are ordinary
/// English or industry words. Without this list `finance.com` is reported as
/// impersonating "binance", `stream.com` as "steam", and `case.com` as
/// "chase".
const COMMON_WORDS: &[&str] = &[
    "stream", "steem", "team", "phase", "chose", "chas", "case", "cases",
    "ample", "amble", "maple", "finance", "credit", "oasis", "basis",
    "reddi", "media", "medias",
];

/// Character pairs that look alike in a browser address bar. Substituting one
/// for another is the classic typosquatting trick ("g00gle", "paypa1"), as
/// opposed to an ordinary spelling difference between two unrelated words.
const CONFUSABLE_GROUPS: &[&str] = &[
    "il1", "o0", "s5", "g9q", "b6", "z2", "a4", "e3", "t7", "uv", "mn", "cek", "rn",
];

fn confusable(a: char, b: char) -> bool {
    CONFUSABLE_GROUPS
        .iter()
        .any(|group| group.contains(a) && group.contains(b))
}

/// Report brand impersonation only for edits that plausibly deceive a reader.
///
/// A bare Levenshtein distance of 1 was far too loose: it scored `finance.com`,
/// `stream.com`, `team.com`, `case.com` and `phase.com` as +60 "brand
/// impersonation", and short brands like "sbi" made `ski`, `sci` and `sbs`
/// look malicious too. An edit now qualifies when it is
///   * an insertion or deletion (doubled or dropped letter: "gogle",
///     "faceboook"), or
///   * a substitution between visually confusable characters ("g00gle",
///     "paypa1", "twltter"),
/// and both names are long enough for the comparison to mean anything.
fn brand_impersonation(candidate: &str, brand: &str) -> Option<String> {
    const MIN_LEN: usize = 5;
    if candidate == brand
        || brand.len() < MIN_LEN
        || candidate.len() < MIN_LEN
        || COMMON_WORDS.contains(&candidate)
    {
        return None;
    }
    if levenshtein(candidate, brand) != 1 {
        return None;
    }
    let deceptive = if candidate.len() == brand.len() {
        // Exactly one differing position, by definition of distance 1.
        candidate
            .chars()
            .zip(brand.chars())
            .find(|(a, b)| a != b)
            .is_some_and(|(a, b)| confusable(a, b))
    } else {
        // An inserted or deleted character: "gogle", "faceboook", "amazonn".
        true
    };
    deceptive.then(|| {
        format!("Possible brand impersonation: '{candidate}' looks like '{brand}'")
    })
}

const NRD_TLDS: &[&str] = &[
    "xyz", "top", "online", "site", "store", "space", "live", "fun", "click", "world", "vip", "cc", "pw", "tk", "ml", "ga", "cf", "gq", "io", "co"
];

/// Levenshtein edit distance.
///
/// Uses a single row of working state instead of a full `Vec<Vec<usize>>`
/// matrix. This is called once per protected brand for every scored domain,
/// so the old version allocated dozens of nested vectors per lookup.
fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let (len_a, len_b) = (a_chars.len(), b_chars.len());

    if len_a == 0 { return len_b; }
    if len_b == 0 { return len_a; }

    let mut previous: Vec<usize> = (0..=len_b).collect();
    for i in 1..=len_a {
        // `diagonal` holds previous[j - 1] from before it was overwritten.
        let mut diagonal = previous[0];
        previous[0] = i;
        for j in 1..=len_b {
            let cost = usize::from(a_chars[i - 1] != b_chars[j - 1]);
            let current = std::cmp::min(
                std::cmp::min(previous[j] + 1, previous[j - 1] + 1),
                diagonal + cost,
            );
            diagonal = previous[j];
            previous[j] = current;
        }
    }
    previous[len_b]
}

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Instant, Duration};

pub struct FastFluxDetector {
    history: HashMap<String, FluxHistory>,
    least_recent: BTreeSet<(u64, String)>,
    sequence: u64,
}

struct FluxHistory {
    resolutions: VecDeque<(Instant, IpAddr)>,
    last_seen: Instant,
    sequence: u64,
}

const MAX_TRACKED_DOMAINS: usize = 10_000;
const HISTORY_TTL: Duration = Duration::from_secs(600);

impl FastFluxDetector {
    pub fn new() -> Self {
        Self {
            history: HashMap::new(),
            least_recent: BTreeSet::new(),
            sequence: 0,
        }
    }

    pub fn record_resolution(&mut self, domain: &str, ip: IpAddr) {
        let domain = domain.to_lowercase();
        let now = Instant::now();
        while let Some((sequence, oldest)) = self.least_recent.first().cloned() {
            let expired = self.history.get(&oldest)
                .map_or(true, |entry| now.duration_since(entry.last_seen) >= HISTORY_TTL);
            if !expired { break; }
            self.least_recent.remove(&(sequence, oldest.clone()));
            self.history.remove(&oldest);
        }

        self.sequence = self.sequence.wrapping_add(1);
        if let Some(entry) = self.history.get_mut(&domain) {
            self.least_recent.remove(&(entry.sequence, domain.clone()));
            entry.last_seen = now;
            entry.sequence = self.sequence;
            entry.resolutions.push_back((now, ip));
            if entry.resolutions.len() > 20 { entry.resolutions.pop_front(); }
        } else {
            if self.history.len() >= MAX_TRACKED_DOMAINS {
                if let Some((_, oldest)) = self.least_recent.pop_first() {
                    debug_assert_ne!(oldest, domain);
                    self.history.remove(&oldest);
                }
            }
            let mut resolutions = VecDeque::new();
            resolutions.push_back((now, ip));
            self.history.insert(domain.clone(), FluxHistory {
                resolutions,
                last_seen: now,
                sequence: self.sequence,
            });
        }
        self.least_recent.insert((self.sequence, domain));
    }

    pub fn is_fast_flux(&mut self, domain: &str) -> bool {
        let domain = domain.to_lowercase();
        
        // Whitelist massive CDNs and services that legitimately rotate IPs wildly (Fast-Flux bypass only)
        let whitelist = [
            // Google / YouTube
            "google.com", "youtube.com", "ytimg.com", "ggpht.com", "googleapis.com", 
            "googleusercontent.com", "gstatic.com", "googlevideo.com", "gvt1.com", "gvt2.com",
            // Microsoft / Azure
            "microsoft.com", "windows.com", "windowsupdate.com", "azure.com", "azureedge.net", 
            "visualstudio.com", "live.com", "office.com", "office.net", "skype.com", "msn.com",
            // Apple
            "apple.com", "icloud.com", "mzstatic.com", "cdn-apple.com",
            // Amazon AWS
            "amazonaws.com", "cloudfront.net",
            // Meta / Facebook
            "facebook.com", "fbcdn.net", "instagram.com", "cdninstagram.com", "whatsapp.net",
            // CDNs
            "cloudflare.com", "cloudflare.net", "fastly.net", "akamai.net", "akamaiedge.net", 
            "akamaihd.net", "edgesuite.net",
            // Streaming / Gaming / Social
            "nflximg.com", "nflxvideo.net", "nflxext.com", "twimg.com", "steamcommunity.com", 
            "steampowered.com", "steamstatic.com", "discord.com", "discordapp.com", 
            "discordapp.net", "reddit.com", "redditmedia.com", "twitch.tv", "ttvnw.net",
            // Dev Tools
            "docker.io", "docker.com", "github.com", "githubcopilot.com", "githubusercontent.com",
            // Hardware
            "lenovo.com", "hp.com", "dell.com",
            // Network & VPN
            "tailscale.com", "tailscale.io", "ts.net"
        ];
        
        for w in &whitelist {
            if domain == *w || domain.ends_with(format!(".{}", w).as_str()) {
                return false;
            }
        }

        if let Some(entry) = self.history.get_mut(&domain) {
            let queue = &mut entry.resolutions;
            let now = Instant::now();
            let ten_mins = Duration::from_secs(600);
            
            // cleanup old
            while let Some(&(time, _)) = queue.front() {
                if now.duration_since(time) > ten_mins {
                    queue.pop_front();
                } else {
                    break;
                }
            }
            
            let mut unique_ips = std::collections::HashSet::new();
            for &(_, ip) in queue.iter() {
                unique_ips.insert(ip);
            }
            
            // Increased from 5 to 10 to account for standard multi-CDN round-robin
            if unique_ips.len() >= 10 {
                let mut all_same_16 = true;
                let mut first_16 = None;
                for ip in &unique_ips {
                    match ip {
                        IpAddr::V4(v4) => {
                            let octets = v4.octets();
                            let prefix = (octets[0], octets[1]);
                            match first_16 {
                                None => first_16 = Some(prefix),
                                Some(p) => {
                                    if p != prefix {
                                        all_same_16 = false;
                                        break;
                                    }
                                }
                            }
                        }
                        IpAddr::V6(_) => {
                            all_same_16 = false;
                            break;
                        }
                    }
                }
                
                if !all_same_16 {
                    return true;
                }
            }
        }
        false
    }
}

/// Score a domain from 0-100 using heuristic analysis.
/// Does NOT make network requests — purely computational.
pub fn score_domain(domain: &str) -> RiskScore {
    let domain = domain.trim_end_matches('.').to_lowercase();
    let domain = domain.trim_start_matches("www.");

    let mut score: i32 = 0;
    let mut factors: Vec<String> = Vec::new();

    // 0. Globally trusted domains (bypasses heuristic scoring completely)
    let trusted = [
        "googleapis.com", "google.com", "gstatic.com", "googleusercontent.com",
        "youtube.com", "youtubei.googleapis.com", "googlevideo.com", "ytimg.com",
        "apple.com", "icloud.com", "mzstatic.com",
        "microsoft.com", "windows.com", "live.com", "office.com", "office365.com",
        "amazon.com", "amazonaws.com", "aws.dev",
        "cloudflare.com", "cloudflare.net",
        "github.com", "githubusercontent.com",
        "netflix.com", "nflxvideo.net",
        "facebook.com", "fbcdn.net",
        "twitter.com", "twimg.com",
        "instagram.com", "cdninstagram.com",
        "tailscale.com", "ts.net"
    ];
    for t in &trusted {
        if domain == *t || domain.ends_with(format!(".{}", t).as_str()) {
            return RiskScore { score: 0, factors: vec!["Trusted top-level domain".into()], level: RiskLevel::Safe };
        }
    }

    let parts: Vec<&str> = domain.split('.').collect();
    let tld = parts.last().copied().unwrap_or("");
    let _base = if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    };
    let name_part = if parts.len() >= 2 { parts[parts.len()-2] } else { domain };

    // 1. Punycode / IDN Homograph (immediate critical signal)
    if domain.contains("xn--") {
        score += 40;
        factors.push("Contains punycode (possible IDN homograph attack)".into());
    }

    // 2. High-risk TLD
    if HIGH_RISK_TLDS.contains(&tld) {
        score += 30;
        factors.push(format!("High-risk TLD: .{}", tld));
    }

    // 3. Suspicious keyword in any label
    let domain_lower = domain.replace('-', "").replace('.', "");
    let mut has_sus_kw = false;
    for kw in SUSPICIOUS_KEYWORDS {
        if domain_lower.contains(kw) {
            score += 25;
            factors.push(format!("Suspicious keyword: '{}'", kw));
            has_sus_kw = true;
            break; // Only penalise once for keyword presence
        }
    }

    // 4. Shannon entropy of the SLD (second-level domain name)
    let entropy = shannon_entropy(name_part);
    if entropy > 3.8 {
        score += 35;
        factors.push(format!("Very high domain entropy ({:.2}) — likely DGA generated", entropy));
    } else if entropy > 3.2 {
        score += 20;
        factors.push(format!("High domain entropy ({:.2})", entropy));
    }

    // 5. Domain length (excessively long SLD is suspicious)
    if name_part.len() > 30 {
        score += 15;
        factors.push(format!("Unusually long domain label ({} chars)", name_part.len()));
    } else if name_part.len() > 20 {
        score += 7;
        factors.push(format!("Long domain label ({} chars)", name_part.len()));
    }

    // 6. Excessive subdomain depth (>3 levels is suspicious)
    let depth = parts.len().saturating_sub(2);
    if depth > 3 {
        score += 15;
        factors.push(format!("Deep subdomain nesting ({} levels)", depth));
    } else if depth > 2 {
        score += 5;
        factors.push(format!("Multiple subdomains ({} levels)", depth));
    }

    // 7. High digit ratio
    let digits: usize = name_part.chars().filter(|c| c.is_ascii_digit()).count();
    let digit_ratio = if name_part.is_empty() { 0.0 } else { digits as f64 / name_part.len() as f64 };
    if digit_ratio > 0.4 {
        score += 12;
        factors.push(format!("High digit ratio ({:.0}% of label is digits)", digit_ratio * 100.0));
    }

    // 8. Hyphens
    let hyphen_count = name_part.chars().filter(|&c| c == '-').count();
    if hyphen_count > 3 {
        score += 10;
        factors.push(format!("{} hyphens in domain label", hyphen_count));
    }

    // 9. Mixed numbers and letters
    let has_mixed = name_part.chars().any(|c| c.is_ascii_digit())
        && name_part.chars().any(|c| c.is_ascii_alphabetic());
    let looks_random = entropy > 3.0 && has_mixed && name_part.len() > 10;
    if looks_random {
        score += 8;
        factors.push("Mixed alphanumeric pattern suggests automated generation".into());
    }
    
    // Feature 3: Typo-Squatting
    let mut base_sld = name_part.to_string();
    let suffixes = ["secure", "login", "account", "online", "official", "app"];
    for s in &suffixes {
        if base_sld.ends_with(s) && base_sld.len() > s.len() {
            let new_len = base_sld.len() - s.len();
            if base_sld.chars().nth(new_len - 1) == Some('-') {
                base_sld.truncate(new_len - 1);
            } else {
                base_sld.truncate(new_len);
            }
        }
    }
    
    for &brand in PROTECTED_BRANDS {
        if let Some(reason) = brand_impersonation(&base_sld, brand) {
            score += 60;
            factors.push(reason);
            break;
        }
    }
    
    // Feature 4: Newly Registered Domain (NRD) Heuristic
    let is_nrd_tld = NRD_TLDS.contains(&tld);
    let no_vowels = !name_part.chars().any(|c| "aeiouy".contains(c));
    let is_high_risk_tld = HIGH_RISK_TLDS.contains(&tld);
    let known_safe = ["google.com", "youtube.com", "facebook.com", "bing.com"].iter().any(|&s| s == domain);

    if (is_nrd_tld && (no_vowels || entropy > 3.5)) || (has_sus_kw && is_high_risk_tld && !known_safe) {
        score += 35;
        factors.push("Lexical risk signal (registration age is unknown)".into());
    }

    // Cap at 100
    let score = score.clamp(0, 100) as u8;

    let level = match score {
        0..=29 => RiskLevel::Safe,
        30..=49 => RiskLevel::Low,
        50..=69 => RiskLevel::Medium,
        70..=84 => RiskLevel::High,
        _ => RiskLevel::Critical,
    };

    if factors.is_empty() {
        factors.push("No significant risk factors detected".into());
    }

    RiskScore { score, factors, level }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_domain() {
        let r = score_domain("github.com");
        assert!(r.score < 30, "github.com should be safe, got {}", r.score);
    }

    #[test]
    fn dga_domain() {
        let r = score_domain("xqk7mn2zpa.xyz");
        assert!(r.score >= 50, "DGA domain should score high, got {}", r.score);
    }

    #[test]
    fn phishing_keyword() {
        let r = score_domain("secure-login-verify.tk");
        assert!(r.score >= 60, "Phishing domain should score high, got {}", r.score);
    }

    /// Ordinary words one edit from a brand must not be accused of
    /// impersonation. Each of these previously scored +60.
    #[test]
    fn ordinary_words_are_not_brand_impersonation() {
        for domain in [
            "finance.com", "stream.com", "case.com", "phase.com",
            "ample.com", "credit.com", "oasis.com",
        ] {
            let r = score_domain(domain);
            assert!(
                !r.factors.iter().any(|f| f.contains("impersonation")),
                "{domain} must not be flagged as brand impersonation: {:?}",
                r.factors
            );
        }
    }

    /// Short brands cannot support a one-edit comparison at all: "ski" and
    /// "sbs" are each one edit from "sbi".
    #[test]
    fn short_names_are_not_compared_to_short_brands() {
        for domain in ["ski.com", "sbs.com", "sci.com", "axi.com"] {
            let r = score_domain(domain);
            assert!(
                !r.factors.iter().any(|f| f.contains("impersonation")),
                "{domain} must not be flagged: {:?}",
                r.factors
            );
        }
    }

    /// Genuine typosquats must still be caught: doubled or dropped letters,
    /// and digit-for-letter swaps that look alike in an address bar.
    #[test]
    fn deceptive_lookalikes_are_still_flagged() {
        // Note: "g00gle" substitutes two characters, so it is edit distance 2
        // and is caught by the other heuristics rather than this one.
        for domain in [
            "gogle.com",     // dropped letter
            "faceboook.com", // doubled letter
            "paypa1.com",    // 1 for l
            "amaz0n.com",    // 0 for o
            "twltter.com",   // l for i
            "disc0rd.com",   // 0 for o
        ] {
            let r = score_domain(domain);
            assert!(
                r.factors.iter().any(|f| f.contains("impersonation")),
                "{domain} should be flagged as impersonation: {:?}",
                r.factors
            );
        }
    }

    #[test]
    fn levenshtein_matches_known_distances() {
        assert_eq!(levenshtein("", "abc"), 3);
        assert_eq!(levenshtein("abc", ""), 3);
        assert_eq!(levenshtein("kitten", "sitting"), 3);
        assert_eq!(levenshtein("google", "gogle"), 1);
        assert_eq!(levenshtein("google", "google"), 0);
    }

    #[test]
    fn full_fast_flux_history_evicts_lru_and_accepts_new_domains() {
        let mut detector = FastFluxDetector::new();
        let ip = "203.0.113.10".parse().unwrap();
        for index in 0..MAX_TRACKED_DOMAINS {
            detector.record_resolution(&format!("{index}.example"), ip);
        }
        detector.record_resolution("new.example", ip);
        assert_eq!(detector.history.len(), MAX_TRACKED_DOMAINS);
        assert!(!detector.history.contains_key("0.example"));
        assert!(detector.history.contains_key("new.example"));
    }
}
