use policy::{PolicyEngine, PolicyDecision};
use blocklist::BlocklistManager;

use serde::Serialize;

#[derive(Serialize)]
pub struct DiagnosticReport {
    pub domain: String,
    pub policy_result: String,
    pub reason: String,
    pub source: String,
    pub action_suggested: String,
}

pub struct DiagnosticEngine;

impl DiagnosticEngine {
    pub fn diagnose(domain: &str, policy: &PolicyEngine, blocklist: &BlocklistManager) -> DiagnosticReport {
        let decision = policy.evaluate(domain, None);
        
        let (policy_result, reason, source, action_suggested) = match decision {
            PolicyDecision::Allowed(ref r) if r == "Explicit user allow" || r == "Temporary allow" => {
                ("ALLOWED".into(), r.clone(), "User Custom Rules".into(), "None, domain is explicitly allowed.".into())
            },
            PolicyDecision::Blocked(_) => {
                ("BLOCKED".into(), "Explicit Deny".into(), "User Custom Rules".into(), "1. Allow domain via 'aegis allow'".into())
            },
            PolicyDecision::Allowed(_) => {
                if blocklist.is_blocked(domain) {
                    ("BLOCKED".into(), "Tracker / Malware / Adult Content".into(), "Enabled Blocklists".into(), "1. Allow domain via 'aegis allow'\n2. Enable Fallback mode via 'aegis fallback'".into())
                } else {
                    ("ALLOWED".into(), "Normal resolution".into(), "Default".into(), "None, domain will be forwarded to Unbound normally.".into())
                }
            }
        };

        DiagnosticReport {
            domain: domain.to_string(),
            policy_result,
            reason,
            source,
            action_suggested,
        }
    }
}
