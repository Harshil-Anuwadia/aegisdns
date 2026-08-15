use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use moka::sync::Cache;
use std::time::Duration;

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
    dedup_cache: Cache<String, ()>,
}

impl AnalyticsDb {
    pub fn new(db_path: PathBuf) -> anyhow::Result<Self> {
        let conn = Connection::open(&db_path)?;
        let db = Self {
            db_path,
            conn: Arc::new(Mutex::new(conn)),
            dedup_cache: Cache::builder()
                .time_to_idle(Duration::from_secs(60))
                .max_capacity(10_000)
                .build(),
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
        conn.execute("CREATE INDEX IF NOT EXISTS idx_client_ip_timestamp ON queries(client_ip, timestamp)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_status_timestamp ON queries(status, timestamp)", [])?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS policy_rules (
                domain TEXT PRIMARY KEY,
                action TEXT
            )",
            [],
        )?;

        // ── Custom DNS Actions Engine ──────────────────────────────────────
        conn.execute(
            "CREATE TABLE IF NOT EXISTS custom_actions (
                domain       TEXT PRIMARY KEY,
                action_type  TEXT NOT NULL,
                payload_url  TEXT,
                method       TEXT DEFAULT 'GET',
                shell_command TEXT,
                html_content TEXT,
                success_msg  TEXT,
                token        TEXT
            )",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS action_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                domain     TEXT NOT NULL,
                triggered_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                outcome    TEXT NOT NULL,
                detail     TEXT
            )",
            [],
        )?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_action_logs_domain ON action_logs(domain)", [])?;
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
        if blocked {
            let key = format!("{}:{}", client_ip, domain);
            if self.dedup_cache.get(&key).is_some() {
                // Deduplicate retry storms: skip logging this blocked query to SQLite
                return Ok(());
            }
            self.dedup_cache.insert(key, ());
        }

        let status = if blocked { "blocked" } else { "allowed" };
        let domain = domain.to_string();
        let client_ip = client_ip.to_string();
        let conn = self.conn.clone();
        
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO queries (domain, status, latency_ms, client_ip) VALUES (?1, ?2, ?3, ?4)",
                rusqlite::params![domain, status, latency_ms, client_ip],
            )
        }).await??;
        
        Ok(())
    }

    pub async fn record_cache_hit(&self, domain: &str, client_ip: &str) -> anyhow::Result<()> {
        let domain = domain.to_string();
        let client_ip = client_ip.to_string();
        let conn = self.conn.clone();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            conn.execute(
                "INSERT INTO queries (domain, status, latency_ms, client_ip) VALUES (?1, 'cache_hit', 0, ?2)",
                rusqlite::params![domain, client_ip],
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

    pub async fn delete_logs(&self, timeframe: &str) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let timeframe = timeframe.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            match timeframe.as_str() {
                "all" => {
                    conn.execute("DELETE FROM queries", [])?;
                }
                "1h" => {
                    conn.execute("DELETE FROM queries WHERE timestamp > datetime('now', '-1 hour')", [])?;
                }
                "24h" => {
                    conn.execute("DELETE FROM queries WHERE timestamp > datetime('now', '-1 day')", [])?;
                }
                "7d" => {
                    conn.execute("DELETE FROM queries WHERE timestamp > datetime('now', '-7 days')", [])?;
                }
                _ => {}
            }
            conn.execute("VACUUM", [])?;
            Ok::<(), anyhow::Error>(())
        })
        .await??;
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
                SUM(CASE WHEN status = 'cache_hit' THEN 1 ELSE 0 END) as cache_hits,
                AVG(latency_ms) as avg_latency
                FROM queries 
                WHERE timestamp >= datetime('now', 'start of day')")?;
            
            let mut rows = stmt.query([])?;
            if let Some(row) = rows.next()? {
                let queries_today: u64 = row.get(0).unwrap_or(0);
                let blocked_today: u64 = row.get(1).unwrap_or(0);
                let allowed_today: u64 = row.get(2).unwrap_or(0);
                let cache_hits: u64 = row.get(3).unwrap_or(0);
                let avg_latency: f64 = row.get(4).unwrap_or(0.0);
                
                Ok(Stats {
                    queries_today,
                    blocked_today,
                    allowed_today,
                    cache_hits,
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
                SUM(CASE WHEN status = 'cache_hit' THEN 1 ELSE 0 END) as cache_hits,
                AVG(latency_ms) as avg_latency
                FROM queries 
                WHERE timestamp >= datetime('now', 'start of day') AND client_ip = ?1")?;
            
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
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE timestamp >= datetime('now', '-24 hours') GROUP BY domain ORDER BY c DESC LIMIT 10")?;
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
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE timestamp >= datetime('now', '-24 hours') AND status = 'blocked' GROUP BY domain ORDER BY c DESC LIMIT 10")?;
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
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE timestamp >= datetime('now', '-24 hours') AND client_ip = ?1 GROUP BY domain ORDER BY c DESC LIMIT 5")?;
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
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE timestamp >= datetime('now', '-24 hours') AND status = 'blocked' AND client_ip = ?1 GROUP BY domain ORDER BY c DESC LIMIT 5")?;
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

    // ── Custom DNS Actions Engine ─────────────────────────────────────────

    pub fn upsert_action(&self, domain: &str, action_type: &str, payload_url: Option<&str>, method: Option<&str>, shell_command: Option<&str>, html_content: Option<&str>, success_msg: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO custom_actions (domain, action_type, payload_url, method, shell_command, html_content, success_msg, token)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(domain) DO UPDATE SET
               action_type   = excluded.action_type,
               payload_url   = excluded.payload_url,
               method        = excluded.method,
               shell_command = excluded.shell_command,
               html_content  = excluded.html_content,
               success_msg   = excluded.success_msg,
               token         = excluded.token",
            rusqlite::params![domain, action_type, payload_url, method, shell_command, html_content, success_msg, token],
        )?;
        Ok(())
    }

    pub fn delete_action(&self, domain: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM custom_actions WHERE domain = ?1", [domain])?;
        Ok(())
    }

    pub fn list_actions(&self) -> anyhow::Result<Vec<CustomAction>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT domain, action_type, payload_url, method, shell_command, html_content, success_msg, token FROM custom_actions ORDER BY domain")?;
        let rows = stmt.query_map([], |row| {
            Ok(CustomAction {
                domain:        row.get(0)?,
                action_type:   row.get(1)?,
                payload_url:   row.get(2)?,
                method:        row.get(3)?,
                shell_command: row.get(4)?,
                html_content:  row.get(5)?,
                success_msg:   row.get(6)?,
                token:         row.get(7)?,
            })
        })?;
        let mut res = Vec::new();
        for r in rows { res.push(r?); }
        Ok(res)
    }

    pub fn get_action(&self, domain: &str) -> Option<CustomAction> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT domain, action_type, payload_url, method, shell_command, html_content, success_msg, token FROM custom_actions WHERE domain = ?1").ok()?;
        stmt.query_row([domain], |row| {
            Ok(CustomAction {
                domain:        row.get(0)?,
                action_type:   row.get(1)?,
                payload_url:   row.get(2)?,
                method:        row.get(3)?,
                shell_command: row.get(4)?,
                html_content:  row.get(5)?,
                success_msg:   row.get(6)?,
                token:         row.get(7)?,
            })
        }).ok()
    }

    pub fn log_action(&self, domain: &str, outcome: &str, detail: Option<&str>) {
        if let Ok(conn) = self.conn.lock() {
            let _ = conn.execute(
                "INSERT INTO action_logs (domain, outcome, detail) VALUES (?1, ?2, ?3)",
                rusqlite::params![domain, outcome, detail],
            );
        }
    }

    pub fn get_action_logs(&self, domain: Option<&str>, limit: u32) -> anyhow::Result<Vec<ActionLog>> {
        let conn = self.conn.lock().unwrap();
        let (sql, param): (String, Box<dyn rusqlite::ToSql>) = if let Some(d) = domain {
            ("SELECT id, domain, triggered_at, outcome, detail FROM action_logs WHERE domain = ?1 ORDER BY triggered_at DESC LIMIT ?2".into(),
             Box::new(format!("{}", d)))
        } else {
            ("SELECT id, domain, triggered_at, outcome, detail FROM action_logs ORDER BY triggered_at DESC LIMIT ?1".into(),
             Box::new(limit as i64))
        };
        let mut stmt = conn.prepare(&sql)?;
        let mut res = Vec::new();
        if domain.is_some() {
            let rows = stmt.query_map(rusqlite::params![param.as_ref(), limit as i64], |row| {
                Ok(ActionLog {
                    id:           row.get(0)?,
                    domain:       row.get(1)?,
                    triggered_at: row.get(2)?,
                    outcome:      row.get(3)?,
                    detail:       row.get(4)?,
                })
            })?;
            for r in rows { res.push(r?); }
        } else {
            let rows = stmt.query_map(rusqlite::params![limit as i64], |row| {
                Ok(ActionLog {
                    id:           row.get(0)?,
                    domain:       row.get(1)?,
                    triggered_at: row.get(2)?,
                    outcome:      row.get(3)?,
                    detail:       row.get(4)?,
                })
            })?;
            for r in rows { res.push(r?); }
        }
        Ok(res)
    }

    pub fn clear_action_logs(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM action_logs", [])?;
        Ok(())
    }
}

// ── Shared data types ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CustomAction {
    pub domain:        String,
    pub action_type:   String,
    pub payload_url:   Option<String>,
    pub method:        Option<String>,
    pub shell_command: Option<String>,
    pub html_content:  Option<String>,
    pub success_msg:   Option<String>,
    pub token:         Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ActionLog {
    pub id:           i64,
    pub domain:       String,
    pub triggered_at: String,
    pub outcome:      String,
    pub detail:       Option<String>,
}

