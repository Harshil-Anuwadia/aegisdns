use serde::{Deserialize,Serialize};
use std::{collections::{HashMap,HashSet},sync::Mutex,time::{SystemTime,UNIX_EPOCH}};

#[derive(Debug,Clone,Serialize,Deserialize,PartialEq,Eq)]
#[serde(default)]
pub struct PrivacyConfig{
    pub enabled:bool,
    pub default_budget:u8,
    pub device_budgets:HashMap<String,u8>,
}
impl Default for PrivacyConfig{fn default()->Self{Self{enabled:false,default_budget:70,device_budgets:HashMap::new()}}}
impl PrivacyConfig{
    pub fn validate(&self)->anyhow::Result<()>{
        anyhow::ensure!((1..=100).contains(&self.default_budget),"Default privacy budget must be between 1 and 100");
        anyhow::ensure!(self.device_budgets.len()<=10_000,"Too many device privacy budgets");
        for (device,budget) in &self.device_budgets{
            anyhow::ensure!(!device.trim().is_empty()&&device.len()<=128,"Invalid device identifier");
            anyhow::ensure!((1..=100).contains(budget),"Device privacy budgets must be between 1 and 100");
        }
        Ok(())
    }
}

#[derive(Default)]
struct DailyActivity{
    day:u64,total:u64,quiet:u64,
    domains:HashSet<String>,companies:HashSet<String>,applications:HashSet<String>,networks:HashSet<String>,countries:HashSet<String>,identifiers:HashSet<String>,
}
impl DailyActivity{
    fn reset_if_needed(&mut self,day:u64){if self.day!=day{*self=Self{day,..Default::default()};}}
    fn score(&self)->u8{
        let uniqueness=if self.total==0{0.0}else{self.domains.len() as f64/self.total as f64};
        let quiet=if self.total==0{0.0}else{self.quiet as f64/self.total as f64};
        ((self.companies.len().min(4)*8+self.identifiers.len().min(20)+self.applications.len().min(5)*2+self.networks.len().min(7)*2+self.countries.len().min(5)*3) as f64+uniqueness*18.0+quiet*10.0).round().min(100.0) as u8
    }
}

pub struct PrivacyGuard{
    config:tokio::sync::RwLock<PrivacyConfig>,
    activity:Mutex<HashMap<String,DailyActivity>>,
    baseline:Mutex<HashMap<String,(u64,u8)>>,
}
impl PrivacyGuard{
    pub fn load()->Self{
        let path=config::paths::get_data_dir().join("privacy.json");
        let cfg=std::fs::read(path).ok().and_then(|bytes|serde_json::from_slice::<PrivacyConfig>(&bytes).ok()).filter(|cfg|cfg.validate().is_ok()).unwrap_or_default();
        Self{config:tokio::sync::RwLock::new(cfg),activity:Mutex::new(HashMap::new()),baseline:Mutex::new(HashMap::new())}
    }
    /// Seed today's scores from persisted analytics so a daemon restart cannot
    /// silently restore tracking access for devices that already spent their budget.
    pub fn seed(&self,summaries:&[analytics::PrivacySummary]){
        let day=current_day();
        let Ok(mut baseline)=self.baseline.lock() else{return;};
        baseline.clear();
        baseline.extend(summaries.iter().take(10_000).map(|summary|(summary.device.clone(),(day,summary.score))));
    }
    pub async fn config(&self)->PrivacyConfig{self.config.read().await.clone()}
    pub async fn save(&self,cfg:PrivacyConfig)->anyhow::Result<()>{
        cfg.validate()?;
        config::atomic_write(config::paths::get_data_dir().join("privacy.json"),serde_json::to_vec_pretty(&cfg)?)?;
        *self.config.write().await=cfg;Ok(())
    }
    pub async fn should_block(&self,device:&str,domain:&str)->bool{
        let cfg=self.config.read().await;
        if !cfg.enabled||!(crate::relationships::tracking_company(domain).is_some()||crate::relationships::contains_identifier(domain)){return false;}
        let budget=cfg.device_budgets.get(device).copied().unwrap_or(cfg.default_budget);
        drop(cfg);
        let day=current_day();
        let live_score=self.activity.lock().ok().and_then(|mut all|{let state=all.entry(device.into()).or_default();state.reset_if_needed(day);Some(state.score())}).unwrap_or(0);
        let baseline_score=self.baseline.lock().ok().and_then(|scores|scores.get(device).copied()).filter(|(saved_day,_)|*saved_day==day).map(|(_,score)|score).unwrap_or(0);
        live_score.max(baseline_score)>=budget
    }
    pub fn record(&self,device:&str,domain:&str,relationships:&[analytics::RelationshipObservation]){
        let day=current_day();let hour=(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()/3600)%24;
        let Ok(mut all)=self.activity.lock() else{return;};
        if all.len()>=10_000&&!all.contains_key(device){return;}
        let state=all.entry(device.into()).or_default();state.reset_if_needed(day);state.total+=1;if hour<6{state.quiet+=1;}state.domains.insert(domain.into());
        for edge in relationships{match edge.target_kind.as_str(){"company"=>{state.companies.insert(edge.target.clone());},"application"=>{state.applications.insert(edge.target.clone());},"network"=>{state.networks.insert(edge.target.clone());},"country"=>{state.countries.insert(edge.target.clone());},_=>{}}
            if edge.relation=="contains_identifier"{state.identifiers.insert(edge.target.clone());}
        }
    }
}
fn current_day()->u64{SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs()/86400}

#[cfg(test)]mod tests{
    use super::*;

    #[test]
    fn config_validation(){
        let mut c=PrivacyConfig::default();
        assert!(c.validate().is_ok());
        c.default_budget=0;
        assert!(c.validate().is_err());
    }

    #[tokio::test]
    async fn persisted_score_survives_restart_for_enforcement(){
        let guard=PrivacyGuard{
            config:tokio::sync::RwLock::new(PrivacyConfig{enabled:true,default_budget:40,device_budgets:HashMap::new()}),
            activity:Mutex::new(HashMap::new()),
            baseline:Mutex::new(HashMap::new()),
        };
        guard.seed(&[analytics::PrivacySummary{
            device:"192.0.2.10".into(),total_queries:10,unique_domains:8,blocked_queries:0,
            tracking_companies:2,advertising_identifiers:1,applications:2,network_spread:2,
            country_spread:1,quiet_hour_queries:0,score:55,
        }]);
        assert!(guard.should_block("192.0.2.10","stats.doubleclick.net").await);
        assert!(!guard.should_block("192.0.2.10","example.com").await);
    }
}
