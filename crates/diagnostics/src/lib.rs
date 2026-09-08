use policy::{PolicyEngine, PolicyDecision};
use blocklist::BlocklistManager;
use serde::Serialize;
#[derive(Serialize)]
pub struct DiagnosticReport {pub domain:String,pub policy_result:String,pub reason:String,pub source:String,pub action_suggested:String}
pub struct DiagnosticEngine;
impl DiagnosticEngine {
    pub fn diagnose(domain:&str,policy:&PolicyEngine,blocklist:&BlocklistManager)->DiagnosticReport {Self::diagnose_for_device(domain,None,"default",policy,blocklist)}
    pub fn diagnose_for_device(domain:&str,device:Option<&str>,profile:&str,policy:&PolicyEngine,blocklist:&BlocklistManager)->DiagnosticReport {
        let domain=config::canonical_domain(domain);
        let decision=policy.evaluate(&domain,device);
        let (blocked,reason,source)=if profile=="bypass" || policy.emergency_mode {(false,"Filtering bypass enabled".into(),"Profile")}
        else {match decision {
            PolicyDecision::Blocked(reason)=>(true,format!("{:?}",reason),"Policy"),
            PolicyDecision::Allowed(reason) if reason.bypass_filtering()=>(false,reason.to_string(),"Policy"),
            _ if blocklist.is_blocked(&domain)=>(true,"Domain matches blocklist".into(),"Blocklist"),
            _ if profile=="strict" && risk::score_domain(&domain).score>=70=>(true,"Strict profile risk threshold".into(),"Risk heuristic"),
            _=>(false,"Allowed before upstream answer inspection; CNAME/rebinding checks may still block".into(),"Policy"),
        }};
        DiagnosticReport{domain,policy_result:if blocked {"BLOCKED"}else{"ALLOWED"}.into(),reason,source:source.into(),action_suggested:if blocked {"Review the matching rule for this device"}else{"None"}.into()}
    }
}
