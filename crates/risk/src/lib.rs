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

const NRD_TLDS: &[&str] = &[
    "xyz", "top", "online", "site", "store", "space", "live", "fun", "click", "world", "vip", "cc", "pw", "tk", "ml", "ga", "cf", "gq", "io", "co"
];

fn levenshtein(a: &str, b: &str) -> usize {
    let a_chars: Vec<char> = a.chars().collect();
    let b_chars: Vec<char> = b.chars().collect();
    let len_a = a_chars.len();
    let len_b = b_chars.len();
    
    if len_a == 0 { return len_b; }
    if len_b == 0 { return len_a; }
    
    let mut dp = vec![vec![0; len_b + 1]; len_a + 1];
    
    for i in 0..=len_a { dp[i][0] = i; }
    for j in 0..=len_b { dp[0][j] = j; }
    
    for i in 1..=len_a {
        for j in 1..=len_b {
            let cost = if a_chars[i - 1] == b_chars[j - 1] { 0 } else { 1 };
            dp[i][j] = std::cmp::min(
                std::cmp::min(dp[i - 1][j] + 1, dp[i][j - 1] + 1),
                dp[i - 1][j - 1] + cost
            );
        }
    }
    
    dp[len_a][len_b]
}

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::time::{Instant, Duration};

pub struct FastFluxDetector {
    history: HashMap<String, VecDeque<(Instant, IpAddr)>>,
}

impl FastFluxDetector {
    pub fn new() -> Self {
        Self {
            history: HashMap::new(),
        }
    }

    pub fn record_resolution(&mut self, domain: &str, ip: IpAddr) {
        let domain = domain.to_lowercase();
        let queue = self.history.entry(domain).or_insert_with(VecDeque::new);
        
        let now = Instant::now();
        queue.push_back((now, ip));
        if queue.len() > 20 {
            queue.pop_front();
        }
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
            "lenovo.com", "hp.com", "dell.com"
        ];
        
        for w in &whitelist {
            if domain == *w || domain.ends_with(format!(".{}", w).as_str()) {
                return false;
            }
        }

        if let Some(queue) = self.history.get_mut(&domain) {
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

    let parts: Vec<&str> = domain.split('.').collect();
    let tld = parts.last().copied().unwrap_or("");
    let _base = if parts.len() >= 2 {
        format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1])
    } else {
        domain.to_string()
    };
    let name_part = parts.first().copied().unwrap_or(&domain);

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
        if base_sld != brand && levenshtein(&base_sld, brand) == 1 {
            score += 60;
            factors.push(format!("Possible brand impersonation: '{}' looks like '{}'", base_sld, brand));
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
        factors.push("Likely newly registered domain — high phishing risk".into());
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
}
