use rusqlite::{params, Connection};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Debug, Default)]
pub struct Stats {
    pub queries_today: u64,
    pub blocked_today: u64,
    pub allowed_today: u64,
    pub cache_hits: u64,
    pub avg_latency_ms: f64,
}

pub struct AnalyticsDb {
    pub db_path: PathBuf,
    conn: Arc<Mutex<Connection>>,
}

impl AnalyticsDb {
    pub fn new(db_path: PathBuf) -> anyhow::Result<Self> {
        let conn = Connection::open(&db_path)?;
        let db = Self {
            db_path,
            conn: Arc::new(Mutex::new(conn)),
        };
        db.initialize_schema()?;
        Ok(db)
    }

    pub fn initialize_schema(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "CREATE TABLE IF NOT EXISTS queries (
                id INTEGER PRIMARY KEY,
                domain TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                status TEXT,
                latency_ms INTEGER,
                client_ip TEXT
            )",
            [],
        )?;
        // Handle migration for existing databases
        let _ = conn.execute("ALTER TABLE queries ADD COLUMN client_ip TEXT", []);
        
        conn.execute("CREATE INDEX IF NOT EXISTS idx_domain ON queries(domain)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON queries(timestamp)", [])?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS policy_rules (
                domain TEXT PRIMARY KEY,
                action TEXT
            )",
            [],
        )?;
        Ok(())
    }

    pub fn load_policy_rules(&self) -> anyhow::Result<(Vec<String>, Vec<String>)> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT domain, action FROM policy_rules")?;
        let mut rows = stmt.query([])?;
        
        let mut allowed = Vec::new();
        let mut denied = Vec::new();
        
        while let Some(row) = rows.next()? {
            let domain: String = row.get(0)?;
            let action: String = row.get(1)?;
            if action == "allow" {
                allowed.push(domain);
            } else if action == "deny" {
                denied.push(domain);
            }
        }
        Ok((allowed, denied))
    }

    pub fn set_policy_rule(&self, domain: &str, action: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO policy_rules (domain, action) VALUES (?1, ?2)
             ON CONFLICT(domain) DO UPDATE SET action=excluded.action",
            [domain, action],
        )?;
        Ok(())
    }

    pub fn remove_policy_rule(&self, domain: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM policy_rules WHERE domain = ?1", [domain])?;
        Ok(())
    }

    pub async fn record_query(&self, domain: &str, blocked: bool, latency_ms: u32, client_ip: &str) -> anyhow::Result<()> {
        let status = if blocked { "blocked" } else { "allowed" };
        let domain = domain.to_string();
        let client_ip = client_ip.to_string();
        let conn = self.conn.clone();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO queries (domain, status, latency_ms, client_ip) VALUES (?1, ?2, ?3, ?4)",
                params![domain, status, latency_ms, client_ip],
            )
        }).await??;
        
        Ok(())
    }

    pub fn cleanup_old_queries(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM queries WHERE timestamp < datetime('now', '-30 days')", [])?;
        conn.execute("VACUUM", [])?;
        Ok(())
    }

    pub async fn get_stats(&self) -> anyhow::Result<Stats> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Stats> {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT 
                COUNT(*) as queries_today,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_today,
                SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed_today,
                0 as cache_hits,
                AVG(latency_ms) as avg_latency
                FROM queries 
                WHERE date(timestamp) = date('now')")?;
            
            let mut rows = stmt.query([])?;
            if let Some(row) = rows.next()? {
                let queries_today: u64 = row.get(0).unwrap_or(0);
                let blocked_today: u64 = row.get(1).unwrap_or(0);
                let allowed_today: u64 = row.get(2).unwrap_or(0);
                let avg_latency: f64 = row.get(4).unwrap_or(0.0);
                
                Ok(Stats {
                    queries_today,
                    blocked_today,
                    allowed_today,
                    cache_hits: 0,
                    avg_latency_ms: avg_latency,
                })
            } else {
                Ok(Stats::default())
            }
        }).await?
    }

    pub async fn get_stats_for_ip(&self, ip: &str) -> anyhow::Result<Stats> {
        let conn = self.conn.clone();
        let ip = ip.to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Stats> {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT 
                COUNT(*) as queries_today,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_today,
                SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed_today,
                0 as cache_hits,
                AVG(latency_ms) as avg_latency
                FROM queries 
                WHERE date(timestamp) = date('now') AND client_ip = ?1")?;
            
            let mut rows = stmt.query([ip])?;
            if let Some(row) = rows.next()? {
                let queries_today: u64 = row.get(0).unwrap_or(0);
                let blocked_today: u64 = row.get(1).unwrap_or(0);
                let allowed_today: u64 = row.get(2).unwrap_or(0);
                let avg_latency: f64 = row.get(4).unwrap_or(0.0);
                
                Ok(Stats {
                    queries_today,
                    blocked_today,
                    allowed_today,
                    cache_hits: 0,
                    avg_latency_ms: avg_latency,
                })
            } else {
                Ok(Stats::default())
            }
        }).await?
    }
    pub async fn get_top_domains(&self) -> anyhow::Result<Vec<(String, u64)>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<(String, u64)>> {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries GROUP BY domain ORDER BY c DESC LIMIT 10")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut res = Vec::new();
            for r in rows { res.push(r?); }
            Ok(res)
        }).await?
    }

    pub async fn get_top_blocked(&self) -> anyhow::Result<Vec<(String, u64)>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<(String, u64)>> {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE status = 'blocked' GROUP BY domain ORDER BY c DESC LIMIT 10")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut res = Vec::new();
            for r in rows { res.push(r?); }
            Ok(res)
        }).await?
    }

    pub async fn get_top_domains_for_ip(&self, ip: &str) -> anyhow::Result<Vec<(String, u64)>> {
        let conn = self.conn.clone();
        let ip = ip.to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<(String, u64)>> {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE client_ip = ?1 GROUP BY domain ORDER BY c DESC LIMIT 5")?;
            let rows = stmt.query_map([ip], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut res = Vec::new();
            for r in rows { res.push(r?); }
            Ok(res)
        }).await?
    }

    pub async fn get_top_blocked_for_ip(&self, ip: &str) -> anyhow::Result<Vec<(String, u64)>> {
        let conn = self.conn.clone();
        let ip = ip.to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<(String, u64)>> {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE status = 'blocked' AND client_ip = ?1 GROUP BY domain ORDER BY c DESC LIMIT 5")?;
            let rows = stmt.query_map([ip], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut res = Vec::new();
            for r in rows { res.push(r?); }
            Ok(res)
        }).await?
    }

    pub async fn get_connected_devices(&self) -> anyhow::Result<Vec<String>> {
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
            let conn = conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT DISTINCT client_ip FROM queries WHERE client_ip IS NOT NULL AND client_ip != '' AND timestamp >= datetime('now', '-1 day')")?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            let mut res = Vec::new();
            for r in rows { res.push(r?); }
            Ok(res)
        }).await?
    }
}
