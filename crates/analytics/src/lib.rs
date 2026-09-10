pub mod aggregation;
use rusqlite::Connection;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use tokio::sync::broadcast;

#[derive(Debug, Default)]
pub struct Stats {
    pub queries_today: u64,
    pub blocked_today: u64,
    pub allowed_today: u64,
    pub cache_hits: u64,
    pub avg_latency_ms: f64,
}


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LiveQueryEvent {
    pub domain: String,
    pub timestamp: String,
    pub status: String,
    pub client_ip: String,
}

#[derive(Clone)]
struct InsertQuery {
    domain: String,
    status: String,
    latency_ms: u32,
    client_ip: String,
    relationships: Vec<RelationshipObservation>,
}

#[derive(Debug, Clone)]
pub struct RelationshipObservation {
    pub source: Option<String>,
    pub source_kind: Option<String>,
    pub relation: String,
    pub target: String,
    pub target_kind: String,
}

enum DbWrite { Query(InsertQuery), Flush(tokio::sync::oneshot::Sender<anyhow::Result<()>>) }

async fn persist_batch(conn:Arc<Mutex<Connection>>,batch:&mut Vec<InsertQuery>)->anyhow::Result<()> {
    if batch.is_empty(){return Ok(());}
    let records=batch.clone();
    tokio::task::spawn_blocking(move ||->anyhow::Result<()> {
        let mut connection=conn.lock().map_err(|_|anyhow::anyhow!("Database mutex poisoned"))?;
        let tx=connection.transaction()?;
        {
            let mut stmt=tx.prepare_cached("INSERT INTO queries (domain,status,latency_ms,client_ip) VALUES (?1,?2,?3,?4)")?;
            let mut relationship_stmt=tx.prepare_cached(
                "INSERT INTO dns_relationships (query_domain, source, source_kind, relation, target, target_kind, client_ip)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)"
            )?;
            for q in records {
                stmt.execute(rusqlite::params![&q.domain,&q.status,q.latency_ms,&q.client_ip])?;
                for edge in q.relationships {
                    let source=edge.source.as_deref().unwrap_or(&q.domain);
                    let source_kind=edge.source_kind.as_deref().unwrap_or("domain");
                    relationship_stmt.execute(rusqlite::params![&q.domain,source,source_kind,edge.relation,edge.target,edge.target_kind,&q.client_ip])?;
                }
            }
        }
        tx.commit()?; Ok(())
    }).await??;
    batch.clear(); Ok(())
}

#[derive(serde::Serialize, Default)]
pub struct Telemetry {
    pub queries: Vec<u64>,
    pub blocked: Vec<u64>,
    pub cache: Vec<u64>,
    pub latency: Vec<f64>,
}

pub struct AnalyticsDb {
    pub db_path: PathBuf,
    conn: Arc<Mutex<Connection>>,
    pub live_tx: broadcast::Sender<LiveQueryEvent>,
    insert_tx: tokio::sync::mpsc::Sender<DbWrite>,
    pub dropped_events: std::sync::atomic::AtomicU64,
}

impl AnalyticsDb {
    pub fn new(db_path: PathBuf) -> anyhow::Result<Self> {
        let conn = Connection::open(&db_path)?;

        let (insert_tx,mut insert_rx)=tokio::sync::mpsc::channel::<DbWrite>(10_000);
        let conn_arc=Arc::new(Mutex::new(conn));
        let conn_clone=conn_arc.clone();
        tokio::spawn(async move {
            let mut batch=Vec::new();
            let mut timer=tokio::time::interval(std::time::Duration::from_millis(500));
            loop {
                tokio::select! {
                    message=insert_rx.recv(), if batch.len()<10_000 => {
                        match message {
                            Some(DbWrite::Query(q))=>{
                                batch.push(q);
                                if batch.len()>=100 {if let Err(e)=persist_batch(conn_clone.clone(),&mut batch).await {tracing::error!("Analytics write failed; batch retained: {}",e);}}
                            }
                            Some(DbWrite::Flush(done))=>{let _=done.send(persist_batch(conn_clone.clone(),&mut batch).await);}
                            None=>{let _=persist_batch(conn_clone.clone(),&mut batch).await;break;}
                        }
                    }
                    _=timer.tick()=>{if let Err(e)=persist_batch(conn_clone.clone(),&mut batch).await {tracing::error!("Analytics retry failed: {}",e);}}
                }
            }
        });

        let db = Self {
            db_path,
            conn: conn_arc,
            live_tx: broadcast::channel(100).0,
            insert_tx,
            dropped_events: std::sync::atomic::AtomicU64::new(0),
        };
        db.initialize_schema()?;
        Ok(db)
    }

    pub fn initialize_schema(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        // WAL mode: readers do not block writers and writers do not block readers.
        // The connection mutex still serializes in-process callers; WAL helps other connections.
        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -10000;
            PRAGMA temp_store = MEMORY;
        ")?;
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
            "CREATE TABLE IF NOT EXISTS dns_relationships (
                id INTEGER PRIMARY KEY,
                observed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                query_domain TEXT NOT NULL,
                source TEXT,
                source_kind TEXT,
                relation TEXT NOT NULL,
                target TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                client_ip TEXT NOT NULL
            )", [],
        )?;
        let _ = conn.execute("ALTER TABLE dns_relationships ADD COLUMN source TEXT", []);
        let _ = conn.execute("ALTER TABLE dns_relationships ADD COLUMN source_kind TEXT", []);
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relationship_domain_time ON dns_relationships(query_domain, observed_at)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relationship_time ON dns_relationships(observed_at)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relationship_source_time ON dns_relationships(source, observed_at)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relationship_client_time ON dns_relationships(client_ip, observed_at)", [])?;
        conn.execute("CREATE INDEX IF NOT EXISTS idx_relationship_target_time ON dns_relationships(target, observed_at)", [])?;

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
        conn.execute(
            "CREATE TABLE IF NOT EXISTS domain_classifications (
                domain TEXT PRIMARY KEY,
                category TEXT NOT NULL
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

    fn enqueue(&self,q:InsertQuery)->anyhow::Result<()> {
        self.insert_tx.try_send(DbWrite::Query(q)).map_err(|_| {
            self.dropped_events.fetch_add(1,std::sync::atomic::Ordering::Relaxed);
            anyhow::anyhow!("Analytics queue full/closed")
        })
    }
    pub async fn flush(&self)->anyhow::Result<()> {
        let (tx,rx)=tokio::sync::oneshot::channel();
        tokio::time::timeout(std::time::Duration::from_secs(5),async {
            self.insert_tx.send(DbWrite::Flush(tx)).await.map_err(|_|anyhow::anyhow!("Analytics worker closed"))?;
            rx.await.map_err(|_|anyhow::anyhow!("Analytics flush canceled"))?
        }).await?
    }

    pub async fn record_failure(&self, domain: &str, client_ip: &str) -> anyhow::Result<()> {
        self.enqueue(InsertQuery { domain:domain.into(), status:"failed".into(), latency_ms:0, client_ip:client_ip.into(), relationships:Vec::new() })?;
        Ok(())
    }

    pub async fn record_query(&self, domain: &str, blocked: bool, latency_ms: u32, client_ip: &str) -> anyhow::Result<()> {
        self.record_query_with_relationships(domain, blocked, latency_ms, client_ip, Vec::new()).await
    }

    pub async fn record_query_with_relationships(&self, domain: &str, blocked: bool, latency_ms: u32, client_ip: &str, relationships: Vec<RelationshipObservation>) -> anyhow::Result<()> {

        let status = if blocked { "blocked" } else { "allowed" };
        let domain = domain.to_string();
        let client_ip = client_ip.to_string();


        if !domain.ends_with(".arpa") && !domain.ends_with(".local") && domain != "localhost" {
            let _ = self.live_tx.send(LiveQueryEvent {
                domain: domain.to_string(),
                timestamp: "".to_string(),
                status: status.to_string(),
                client_ip: client_ip.to_string(),
            });
        }

        self.enqueue(InsertQuery {
            domain,
            status: status.to_string(),
            latency_ms,
            client_ip,
            relationships,
        }).map_err(|e| anyhow::anyhow!("Analytics queue full/closed: {}", e))?;

        Ok(())
    }

    pub async fn record_cache_hit(&self, domain: &str, client_ip: &str) -> anyhow::Result<()> {
        let domain = domain.to_string();
        let client_ip = client_ip.to_string();

        if !domain.ends_with(".arpa") && !domain.ends_with(".local") && domain != "localhost" {
            let _ = self.live_tx.send(LiveQueryEvent {
                domain: domain.to_string(),
                timestamp: "".to_string(),
                status: "cache_hit".to_string(),
                client_ip: client_ip.to_string(),
            });
        }

        self.enqueue(InsertQuery {
            domain,
            status: "cache_hit".to_string(),
            latency_ms: 0,
            client_ip,
            relationships: Vec::new(),
        }).map_err(|e| anyhow::anyhow!("Analytics queue full/closed: {}", e))?;

        Ok(())
    }

    pub fn cleanup_old_queries(&self) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        // Time-based TTL: drop anything older than 30 days.
        conn.execute("DELETE FROM queries WHERE timestamp < datetime('now', '-30 days')", [])?;
        // Row-count cap: keep at most 1,000,000 rows so disk usage stays bounded on
        // small hosts (Raspberry Pi, etc.) even on high-traffic networks.
        conn.execute(
            "DELETE FROM queries WHERE id < (SELECT id FROM queries ORDER BY id DESC LIMIT 1 OFFSET 999999)",
            [],
        )?;
        conn.execute("DELETE FROM dns_relationships WHERE observed_at < datetime('now', '-30 days')", [])?;
        conn.execute(
            "DELETE FROM dns_relationships WHERE id < (SELECT id FROM dns_relationships ORDER BY id DESC LIMIT 1 OFFSET 1999999)",
            [],
        )?;
        conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
        Ok(())
    }

    pub async fn relationship_graph(&self, domain: Option<&str>, hours: u32) -> anyhow::Result<RelationshipGraph> {
        self.relationship_graph_with_options(domain, hours, 80, 1).await
    }

    pub async fn relationship_graph_with_options(&self, domain: Option<&str>, hours: u32, edge_limit: u32, min_count: u32) -> anyhow::Result<RelationshipGraph> {
        let db_path = self.db_path.clone();
        let domain = domain.map(|value|value.trim().trim_end_matches('.').to_ascii_lowercase()).filter(|value| !value.is_empty());
        let hours = hours.clamp(1, 24 * 30);
        let edge_limit = edge_limit.clamp(20, 200);
        let min_count = min_count.clamp(1, 10_000);
        let observation_limit = if domain.is_some() { 250_000 } else { 100_000 };
        tokio::task::spawn_blocking(move || -> anyhow::Result<RelationshipGraph> {
            let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let window = format!("-{hours} hours");
            let sql = if domain.is_some() {
                "WITH recent AS (
                    SELECT query_domain,source,source_kind,relation,target,target_kind,observed_at
                    FROM dns_relationships WHERE observed_at >= datetime('now', ?1)
                    ORDER BY observed_at DESC LIMIT ?2
                 ), matched AS (
                    SELECT DISTINCT query_domain FROM recent
                    WHERE query_domain = ?3 OR source = ?3 OR target = ?3
                 )
                 SELECT COALESCE(source,query_domain),COALESCE(source_kind,'domain'),relation,target,target_kind,COUNT(*),MIN(observed_at),MAX(observed_at)
                 FROM recent WHERE query_domain IN (SELECT query_domain FROM matched)
                 GROUP BY COALESCE(source,query_domain),COALESCE(source_kind,'domain'),relation,target,target_kind
                 HAVING COUNT(*) >= ?4
                 ORDER BY CASE WHEN COALESCE(source,query_domain) = ?3 OR target = ?3 THEN 0 ELSE 1 END,
                          COUNT(*) DESC, MAX(observed_at) DESC LIMIT ?5"
            } else {
                "WITH recent AS (
                    SELECT query_domain,source,source_kind,relation,target,target_kind,observed_at
                    FROM dns_relationships WHERE observed_at >= datetime('now', ?1)
                    ORDER BY observed_at DESC LIMIT ?2
                 )
                 SELECT COALESCE(source,query_domain),COALESCE(source_kind,'domain'),relation,target,target_kind,COUNT(*),MIN(observed_at),MAX(observed_at)
                 FROM recent
                 GROUP BY COALESCE(source,query_domain),COALESCE(source_kind,'domain'),relation,target,target_kind
                 HAVING COUNT(*) >= ?3
                 ORDER BY COUNT(*) DESC, MAX(observed_at) DESC LIMIT ?4"
            };
            let mut stmt = conn.prepare(sql)?;
            let map_row = |row: &rusqlite::Row<'_>| -> rusqlite::Result<RelationshipEdge> {
                let source: String = row.get(0)?;
                let source_kind: String = row.get(1)?;
                let target: String = row.get(3)?;
                let target_kind: String = row.get(4)?;
                Ok(RelationshipEdge { source:format!("{source_kind}:{source}"), target:format!("{target_kind}:{target}"), relation:row.get(2)?, count:row.get(5)?, first_seen:row.get(6)?, last_seen:row.get(7)? })
            };
            let mut edges=Vec::new();
            if let Some(ref selected)=domain {
                for row in stmt.query_map(rusqlite::params![window,observation_limit,selected,min_count,edge_limit + 1],map_row)? { edges.push(row?); }
            } else {
                for row in stmt.query_map(rusqlite::params![window,observation_limit,min_count,edge_limit + 1],map_row)? { edges.push(row?); }
            }
            let truncated=edges.len() > edge_limit as usize;
            edges.truncate(edge_limit as usize);
            let mut nodes=std::collections::BTreeMap::new();
            for edge in &edges {
                for id in [&edge.source,&edge.target] {
                    let (kind,label)=id.split_once(':').unwrap_or(("domain",id));
                    nodes.entry(id.clone()).or_insert_with(||RelationshipNode{id:id.clone(),label:label.into(),kind:kind.into()});
                }
            }
            Ok(RelationshipGraph{nodes:nodes.into_values().collect(),edges,hours,edge_limit,min_count,truncated,observation_limit})
        }).await?
    }

    pub async fn privacy_summaries(&self) -> anyhow::Result<Vec<PrivacySummary>> {
        let db_path=self.db_path.clone();
        tokio::task::spawn_blocking(move ||->anyhow::Result<Vec<PrivacySummary>> {
            let conn=Connection::open_with_flags(db_path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let mut stmt=conn.prepare("SELECT client_ip,COUNT(*),COUNT(DISTINCT domain),SUM(status='blocked'),SUM(CAST(strftime('%H',timestamp) AS INTEGER)<6) FROM queries WHERE timestamp>=datetime('now','start of day') AND client_ip!='' GROUP BY client_ip ORDER BY COUNT(*) DESC")?;
            let rows=stmt.query_map([],|r|Ok((r.get::<_,String>(0)?,r.get::<_,u64>(1)?,r.get::<_,u64>(2)?,r.get::<_,u64>(3)?,r.get::<_,u64>(4)?)))?;
            let mut output=Vec::new();
            for row in rows {
                let (device,total,unique,blocked,quiet)=row?;
                let distinct=|kind:&str,relation:Option<&str>|->anyhow::Result<u64>{
                    Ok(if let Some(relation)=relation {
                        conn.query_row("SELECT COUNT(DISTINCT target) FROM dns_relationships WHERE client_ip=?1 AND observed_at>=datetime('now','start of day') AND target_kind=?2 AND relation=?3",rusqlite::params![&device,kind,relation],|r|r.get(0))?
                    } else {
                        conn.query_row("SELECT COUNT(DISTINCT target) FROM dns_relationships WHERE client_ip=?1 AND observed_at>=datetime('now','start of day') AND target_kind=?2",rusqlite::params![&device,kind],|r|r.get(0))?
                    })
                };
                let tracking_companies=distinct("company",None)?;
                let advertising_identifiers=distinct("domain",Some("contains_identifier"))?;
                let applications=distinct("application",None)?;
                let network_spread=distinct("network",None)?;
                let country_spread=distinct("country",None)?;
                let uniqueness=if total==0{0.0}else{unique as f64/total as f64};
                let quiet_ratio=if total==0{0.0}else{quiet as f64/total as f64};
                let score=((tracking_companies.min(4)*8+advertising_identifiers.min(20)+applications.min(5)*2+network_spread.min(7)*2+country_spread.min(5)*3) as f64+uniqueness*18.0+quiet_ratio*10.0).round().min(100.0) as u8;
                output.push(PrivacySummary{device,total_queries:total,unique_domains:unique,blocked_queries:blocked,tracking_companies,advertising_identifiers,applications,network_spread,country_spread,quiet_hour_queries:quiet,score});
            }
            Ok(output)
        }).await?
    }


    pub async fn get_queries_for_export(&self, status_filter: Option<&str>, ip_filter: Option<&str>, days: u32) -> anyhow::Result<Vec<RecentQuery>> {
        let db_path = self.db_path.clone();
        let status_filter = status_filter.map(str::to_owned);
        let ip_filter = ip_filter.map(str::to_owned);
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<RecentQuery>> {
        let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut res = Vec::new();

        let mut query = "SELECT domain, timestamp, status, client_ip FROM queries WHERE timestamp >= datetime('now', ?) ".to_string();
        let mut params: Vec<String> = vec![format!("-{} days", days)];

        if let Some(ip) = ip_filter.as_deref() {
            if !ip.is_empty() && ip != "all" {
                query.push_str(&format!("AND client_ip = ?{} ", params.len() + 1));
                params.push(ip.to_string());
            }
        }

        if let Some(status) = status_filter.as_deref() {
            if !status.is_empty() && status != "all" {
                query.push_str(&format!("AND status = ?{} ", params.len() + 1));
                params.push(status.to_string());
            }
        }

        query.push_str("ORDER BY timestamp DESC");

        let mut stmt = conn.prepare(&query)?;

        let rusqlite_params = rusqlite::params_from_iter(params.iter());
        let mut rows = stmt.query(rusqlite_params)?;

        while let Some(row) = rows.next()? {
            res.push(RecentQuery {
                domain: row.get(0)?,
                timestamp: row.get(1)?,
                status: row.get(2)?,
                client_ip: row.get(3)?,
            });
        }
        Ok(res)
        }).await?
    }

    pub async fn get_recent_queries(&self, limit: u32, ip_filter: Option<&str>) -> anyhow::Result<Vec<RecentQuery>> {
        let db_path = self.db_path.clone();
        let ip_filter = ip_filter.map(str::to_owned);
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<RecentQuery>> {
        let conn = Connection::open_with_flags(db_path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
        let mut res = Vec::new();

        if let Some(ip) = ip_filter.as_deref() {
            let mut stmt = conn.prepare("SELECT domain, timestamp, status, client_ip FROM queries WHERE client_ip = ?1 AND domain NOT LIKE '%.arpa' AND domain != 'localhost' AND domain NOT LIKE '%.local' ORDER BY timestamp DESC LIMIT ?2")?;
            let mut rows = stmt.query(rusqlite::params![ip, limit])?;
            while let Some(row) = rows.next()? {
                res.push(RecentQuery {
                    domain: row.get(0)?,
                    timestamp: row.get(1)?,
                    status: row.get(2)?,
                    client_ip: row.get(3)?,
                });
            }
        } else {
            let mut stmt = conn.prepare("SELECT domain, timestamp, status, client_ip FROM queries WHERE domain NOT LIKE '%.arpa' AND domain != 'localhost' AND domain NOT LIKE '%.local' ORDER BY timestamp DESC LIMIT ?1")?;
            let mut rows = stmt.query(rusqlite::params![limit])?;
            while let Some(row) = rows.next()? {
                res.push(RecentQuery {
                    domain: row.get(0)?,
                    timestamp: row.get(1)?,
                    status: row.get(2)?,
                    client_ip: row.get(3)?,
                });
            }
        }
        Ok(res)
        }).await?
    }

    pub fn get_domain_insights(&self, domain: &str) -> anyhow::Result<DomainInsight> {
        let conn = self.conn.lock().unwrap();

        let mut stmt = conn.prepare("
            SELECT
                COUNT(*) as total,
                MIN(timestamp) as first_seen,
                MAX(timestamp) as last_seen,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_count,
                SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed_count,
                SUM(CASE WHEN status = 'cache_hit' THEN 1 ELSE 0 END) as cached_count
            FROM queries
            WHERE domain = ?1
        ")?;

        let mut total_requests = 0;
        let mut first_seen = String::new();
        let mut last_seen = String::new();
        let mut blocked_count = 0;
        let mut allowed_count = 0;
        let mut cached_count = 0;

        let mut rows = stmt.query([domain])?;
        if let Some(row) = rows.next()? {
            total_requests = row.get(0).unwrap_or(0);
            first_seen = row.get(1).unwrap_or_else(|_| "Never".to_string());
            last_seen = row.get(2).unwrap_or_else(|_| "Never".to_string());
            blocked_count = row.get(3).unwrap_or(0);
            allowed_count = row.get(4).unwrap_or(0);
            cached_count = row.get(5).unwrap_or(0);
        }

        let mut stmt_dev = conn.prepare("
            SELECT client_ip, COUNT(*) as c
            FROM queries
            WHERE domain = ?1
            GROUP BY client_ip
            ORDER BY c DESC
            LIMIT 5
        ")?;

        let mut devices = Vec::new();
        let mut rows_dev = stmt_dev.query([domain])?;
        while let Some(row) = rows_dev.next()? {
            devices.push(DeviceInsight {
                ip: row.get(0)?,
                count: row.get(1)?,
            });
        }

        Ok(DomainInsight {
            domain: domain.to_string(),
            total_requests,
            first_seen,
            last_seen,
            devices,
            blocked_count,
            allowed_count,
            cached_count,
        })
    }

    pub async fn delete_logs(&self, timeframe: &str) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let timeframe = timeframe.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            match timeframe.as_str() {
                "all" => {
                    conn.execute("DELETE FROM queries", [])?;
                    conn.execute("DELETE FROM dns_relationships", [])?;
                }
                "1h" => {
                    conn.execute("DELETE FROM queries WHERE timestamp > datetime('now', '-1 hour')", [])?;
                    conn.execute("DELETE FROM dns_relationships WHERE observed_at > datetime('now', '-1 hour')", [])?;
                }
                "24h" => {
                    conn.execute("DELETE FROM queries WHERE timestamp > datetime('now', '-1 day')", [])?;
                    conn.execute("DELETE FROM dns_relationships WHERE observed_at > datetime('now', '-1 day')", [])?;
                }
                "7d" => {
                    conn.execute("DELETE FROM queries WHERE timestamp > datetime('now', '-7 days')", [])?;
                    conn.execute("DELETE FROM dns_relationships WHERE observed_at > datetime('now', '-7 days')", [])?;
                }
                _ => {}
            }
            conn.execute_batch("PRAGMA wal_checkpoint(PASSIVE);")?;
            Ok::<(), anyhow::Error>(())
        })
        .await??;
        Ok(())
    }

    pub async fn get_stats(&self) -> anyhow::Result<Stats> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Stats> {
            let conn = Connection::open_with_flags(db_path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let mut stmt = conn.prepare("SELECT
                COUNT(*) as queries_today,
                SUM(CASE WHEN status = 'blocked' THEN 1 ELSE 0 END) as blocked_today,
                SUM(CASE WHEN status = 'allowed' THEN 1 ELSE 0 END) as allowed_today,
                SUM(CASE WHEN status = 'cache_hit' THEN 1 ELSE 0 END) as cache_hits
                FROM queries
                WHERE timestamp >= datetime('now', 'start of day')")?;

            let mut rows = stmt.query([])?;
            if let Some(row) = rows.next()? {
                let queries_today: u64 = row.get(0).unwrap_or(0);
                let blocked_today: u64 = row.get(1).unwrap_or(0);
                let allowed_today: u64 = row.get(2).unwrap_or(0);
                let cache_hits: u64 = row.get(3).unwrap_or(0);

                // Rolling 5-minute average: reflects actual current performance,
                // not a cumulative all-day average that gets polluted by old slow queries.
                let avg_latency_ms = {
                    let mut lat_stmt = conn.prepare(
                        "SELECT AVG(latency_ms) FROM queries \
                         WHERE status = 'allowed' \
                         AND latency_ms > 0 \
                         AND timestamp >= datetime('now', '-5 minutes')"
                    )?;
                    let mut lat_rows = lat_stmt.query([])?;
                    if let Some(lat_row) = lat_rows.next()? {
                        lat_row.get::<_, f64>(0).unwrap_or(0.0)
                    } else {
                        0.0
                    }
                };

                Ok(Stats {
                    queries_today,
                    blocked_today,
                    allowed_today,
                    cache_hits,
                    avg_latency_ms,
                })
            } else {
                Ok(Stats::default())
            }
        }).await?
    }


    pub async fn get_telemetry(&self) -> anyhow::Result<Telemetry> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Telemetry> {
            let conn = Connection::open_with_flags(db_path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;

            let mut stmt = conn.prepare("
                SELECT strftime('%s', timestamp), status, latency_ms
                FROM queries
                WHERE timestamp >= datetime('now', '-60 seconds')
            ")?;

            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
            let mut queries = vec![0; 60];
            let mut blocked = vec![0; 60];
            let mut cache = vec![0; 60];
            let mut latency = vec![0.0; 60];
            let mut latency_count = vec![0; 60];

            let mut rows = stmt.query([])?;
            while let Some(row) = rows.next()? {
                let ts: i64 = row.get::<_, String>(0)?.parse().unwrap_or(now);
                let status: String = row.get(1)?;
                let lat: f64 = row.get::<_, f64>(2).unwrap_or(0.0);

                let diff = (now - ts) as usize;
                if diff < 60 {
                    let idx = 59 - diff;
                    queries[idx] += 1;
                    if status == "blocked" {
                        blocked[idx] += 1;
                    } else if status == "cache_hit" {
                        cache[idx] += 1;
                    }
                    if lat > 0.0 {
                        latency[idx] += lat;
                        latency_count[idx] += 1;
                    }
                }
            }

            for i in 0..60 {
                if latency_count[i] > 0 {
                    latency[i] /= latency_count[i] as f64;
                }
            }

            Ok(Telemetry {
                queries,
                blocked,
                cache,
                latency,
            })
        }).await?
    }

    pub async fn get_stats_for_ip(&self, ip: &str) -> anyhow::Result<Stats> {
        let db_path = self.db_path.clone();
        let ip = ip.to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Stats> {
            let conn = Connection::open_with_flags(db_path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
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
    pub async fn get_top_domains(&self) -> anyhow::Result<aggregation::AggregatedDomains> {
        let db_path = self.db_path.clone();
        let classifications = self.get_all_classifications();
        tokio::task::spawn_blocking(move || -> anyhow::Result<aggregation::AggregatedDomains> {
            let conn = Connection::open_with_flags(db_path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE timestamp >= datetime('now', 'start of day') AND domain NOT LIKE '%.arpa' AND domain != 'localhost' AND domain NOT LIKE '%.local' GROUP BY domain ORDER BY c DESC LIMIT 1000")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut res = Vec::new();
            for r in rows { res.push(r?); }
            Ok(aggregation::aggregate_and_classify_domains(res, &classifications))
        }).await?
    }

    pub async fn get_top_blocked(&self) -> anyhow::Result<Vec<(String, u64)>> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<(String, u64)>> {
            let conn = Connection::open_with_flags(db_path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE timestamp >= datetime('now', 'start of day') AND status = 'blocked' AND domain NOT LIKE '%.arpa' AND domain != 'localhost' AND domain NOT LIKE '%.local' GROUP BY domain ORDER BY c DESC LIMIT 10")?;
            let rows = stmt.query_map([], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut res = Vec::new();
            for r in rows { res.push(r?); }
            Ok(res)
        }).await?
    }

    pub async fn get_top_domains_for_ip(&self, ip: &str) -> anyhow::Result<aggregation::AggregatedDomains> {
        let db_path = self.db_path.clone();
        let ip = ip.to_string();
        let classifications = self.get_all_classifications();
        tokio::task::spawn_blocking(move || -> anyhow::Result<aggregation::AggregatedDomains> {
            let conn = Connection::open_with_flags(db_path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE timestamp >= datetime('now', 'start of day') AND client_ip = ?1 AND domain NOT LIKE '%.arpa' AND domain != 'localhost' AND domain NOT LIKE '%.local' GROUP BY domain ORDER BY c DESC LIMIT 1000")?;
            let rows = stmt.query_map([ip], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut res = Vec::new();
            for r in rows { res.push(r?); }
            Ok(aggregation::aggregate_and_classify_domains(res, &classifications))
        }).await?
    }

    pub async fn get_top_blocked_for_ip(&self, ip: &str) -> anyhow::Result<Vec<(String, u64)>> {
        let db_path = self.db_path.clone();
        let ip = ip.to_string();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<(String, u64)>> {
            let conn = Connection::open_with_flags(db_path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
            let mut stmt = conn.prepare("SELECT domain, COUNT(*) as c FROM queries WHERE timestamp >= datetime('now', 'start of day') AND status = 'blocked' AND client_ip = ?1 AND domain NOT LIKE '%.arpa' AND domain != 'localhost' AND domain NOT LIKE '%.local' GROUP BY domain ORDER BY c DESC LIMIT 5")?;
            let rows = stmt.query_map([ip], |row| Ok((row.get(0)?, row.get(1)?)))?;
            let mut res = Vec::new();
            for r in rows { res.push(r?); }
            Ok(res)
        }).await?
    }

    pub async fn get_connected_devices(&self) -> anyhow::Result<Vec<String>> {
        let db_path = self.db_path.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<Vec<String>> {
            let conn = Connection::open_with_flags(db_path,rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)?;
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

    pub fn log_latency(&self, domain: &str, latency_ms: u64, ip: &str) {
        if domain == "localhost" || domain.ends_with(".local") { return; }
        let conn = self.conn.lock().unwrap();
        let _ = conn.execute(
            "UPDATE queries SET latency_ms = ?1 WHERE domain = ?2 AND client_ip = ?3 AND timestamp >= datetime('now', '-1 minute')",
            rusqlite::params![latency_ms as i64, domain, ip],
        );
    }

    pub fn get_all_classifications(&self) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        if let Ok(conn) = self.conn.lock() {
            if let Ok(mut stmt) = conn.prepare("SELECT domain, category FROM domain_classifications") {
                if let Ok(rows) = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))) {
                    for r in rows.flatten() {
                        map.insert(r.0, r.1);
                    }
                }
            }
        }
        map
    }

    pub async fn set_classification(&self, domain: &str, category: &str) -> anyhow::Result<()> {
        let conn = self.conn.clone();
        let d = domain.to_string();
        let c = category.to_string();
        tokio::task::spawn_blocking(move || {
            let conn = conn.lock().unwrap();
            if c == "reset" || c == "clear" {
                conn.execute("DELETE FROM domain_classifications WHERE domain = ?1", rusqlite::params![d])?;
            } else {
                conn.execute(
                    "INSERT OR REPLACE INTO domain_classifications (domain, category) VALUES (?1, ?2)",
                    rusqlite::params![d, c],
                )?;
            }
            Ok(())
        }).await?
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
pub struct ActionLog {
    pub id:           i64,
    pub domain:       String,
    pub triggered_at: String,
    pub outcome:      String,
    pub detail:       Option<String>,
}


#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RecentQuery {
    pub domain: String,
    pub timestamp: String,
    pub status: String,
    pub client_ip: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceInsight {
    pub ip: String,
    pub count: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DomainInsight {
    pub domain: String,
    pub total_requests: u64,
    pub first_seen: String,
    pub last_seen: String,
    pub devices: Vec<DeviceInsight>,
    pub blocked_count: u64,
    pub allowed_count: u64,
    pub cached_count: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelationshipNode {
    pub id: String,
    pub label: String,
    pub kind: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelationshipEdge {
    pub source: String,
    pub target: String,
    pub relation: String,
    pub count: u64,
    pub first_seen: String,
    pub last_seen: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelationshipGraph {
    pub nodes: Vec<RelationshipNode>,
    pub edges: Vec<RelationshipEdge>,
    pub hours: u32,
    pub edge_limit: u32,
    pub min_count: u32,
    pub truncated: bool,
    pub observation_limit: u32,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PrivacySummary {
    pub device: String,
    pub total_queries: u64,
    pub unique_domains: u64,
    pub blocked_queries: u64,
    pub tracking_companies: u64,
    pub advertising_identifiers: u64,
    pub applications: u64,
    pub network_spread: u64,
    pub country_spread: u64,
    pub quiet_hour_queries: u64,
    pub score: u8,
}

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

#[cfg(test)] mod regression_tests {
    use super::*;
    fn test_path(label:&str)->PathBuf{
        std::env::temp_dir().join(format!("aegis-analytics-{label}-{}-{}.db",std::process::id(),std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_nanos()))
    }

    #[tokio::test] async fn repeated_queries_count_and_flush() {
        let path=test_path("flush");
        let db=AnalyticsDb::new(path.clone()).unwrap();
        for _ in 0..5 {db.record_query("blocked.example",true,0,"192.168.1.2").await.unwrap();}
        db.record_failure("failed.example","192.168.1.2").await.unwrap();
        db.flush().await.unwrap();
        assert_eq!(db.get_stats().await.unwrap().blocked_today,5);
        assert_eq!(db.get_recent_queries(20,None).await.unwrap().len(),6);
        drop(db);let _=std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn relationships_and_privacy_are_aggregated_and_deleted_together(){
        let path=test_path("relationships");
        let db=AnalyticsDb::new(path.clone()).unwrap();
        db.record_query_with_relationships("stats.doubleclick.net",false,3,"192.0.2.8",vec![
            RelationshipObservation{source:None,source_kind:None,relation:"requested_by".into(),target:"192.0.2.8".into(),target_kind:"device".into()},
            RelationshipObservation{source:None,source_kind:None,relation:"contacts".into(),target:"Google".into(),target_kind:"company".into()},
            RelationshipObservation{source:Some("edge.example".into()),source_kind:Some("domain".into()),relation:"resolves_to".into(),target:"203.0.113.7".into(),target_kind:"ip".into()},
            RelationshipObservation{source:None,source_kind:None,relation:"used_by".into(),target:"Example TV".into(),target_kind:"application".into()},
        ]).await.unwrap();
        db.flush().await.unwrap();

        let graph=db.relationship_graph(Some("stats.doubleclick.net"),24).await.unwrap();
        assert!(graph.nodes.iter().any(|node|node.id=="company:Google"));
        assert!(graph.edges.iter().any(|edge|edge.source=="domain:edge.example"&&edge.relation=="resolves_to"&&edge.count==1));
        let related=db.relationship_graph(Some("edge.example"),24).await.unwrap();
        assert!(related.edges.iter().any(|edge|edge.relation=="requested_by"&&edge.target=="device:192.0.2.8"));
        let bounded=db.relationship_graph_with_options(None,24,1,1).await.unwrap();
        assert_eq!(bounded.edge_limit,20);
        assert!(!bounded.truncated);
        let filtered=db.relationship_graph_with_options(None,24,20,2).await.unwrap();
        assert!(filtered.edges.is_empty());
        let summaries=db.privacy_summaries().await.unwrap();
        assert_eq!(summaries.len(),1);
        assert_eq!(summaries[0].tracking_companies,1);
        assert_eq!(summaries[0].applications,1);

        db.delete_logs("all").await.unwrap();
        assert!(db.relationship_graph(None,24).await.unwrap().edges.is_empty());
        drop(db);let _=std::fs::remove_file(path);
    }
}
