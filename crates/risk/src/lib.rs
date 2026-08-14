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
    for kw in SUSPICIOUS_KEYWORDS {
        if domain_lower.contains(kw) {
            score += 25;
            factors.push(format!("Suspicious keyword: '{}'", kw));
            break; // Only penalise once for keyword presence
        }
    }

    // 4. Shannon entropy of the SLD (second-level domain name)
    // DGA domains are near-random and have entropy > 3.5
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
    let depth = parts.len().saturating_sub(2); // exclude TLD + SLD
    if depth > 3 {
        score += 15;
        factors.push(format!("Deep subdomain nesting ({} levels)", depth));
    } else if depth > 2 {
        score += 5;
        factors.push(format!("Multiple subdomains ({} levels)", depth));
    }

    // 7. High digit ratio (abc123def456 style = suspicious)
    let digits: usize = name_part.chars().filter(|c| c.is_ascii_digit()).count();
    let digit_ratio = if name_part.is_empty() { 0.0 } else { digits as f64 / name_part.len() as f64 };
    if digit_ratio > 0.4 {
        score += 12;
        factors.push(format!("High digit ratio ({:.0}% of label is digits)", digit_ratio * 100.0));
    }

    // 8. Consecutive hyphens or hyphens at unusual positions (beyond normal internationalization)
    let hyphen_count = name_part.chars().filter(|&c| c == '-').count();
    if hyphen_count > 3 {
        score += 10;
        factors.push(format!("{} hyphens in domain label", hyphen_count));
    }

    // 9. Mixed numbers and letters in a random-looking pattern
    let has_mixed = name_part.chars().any(|c| c.is_ascii_digit())
        && name_part.chars().any(|c| c.is_ascii_alphabetic());
    let looks_random = entropy > 3.0 && has_mixed && name_part.len() > 10;
    if looks_random {
        score += 8;
        factors.push("Mixed alphanumeric pattern suggests automated generation".into());
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
