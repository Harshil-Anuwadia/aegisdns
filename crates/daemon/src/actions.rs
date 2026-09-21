use analytics::{AnalyticsDb, CustomAction};
use moka::sync::Cache;
use std::{collections::HashSet, sync::{Arc, OnceLock, RwLock}};
use std::time::Duration;
use sha2::{Sha256, Digest};

// ── Process-level moka cache (hot path for DNS) ───────────────────────────────
static ACTION_CACHE: OnceLock<Cache<String, Option<CustomAction>>> = OnceLock::new();

fn cache() -> &'static Cache<String, Option<CustomAction>> {
    ACTION_CACHE.get_or_init(|| {
        Cache::builder()
            .max_capacity(1_000)
            .time_to_live(Duration::from_secs(30))
            .build()
    })
}

#[derive(Clone, Default)]
pub struct ActionDomains(Arc<RwLock<HashSet<String>>>);

impl ActionDomains {
    pub fn load(db:&AnalyticsDb)->anyhow::Result<Self> {
        Ok(Self(Arc::new(RwLock::new(db.list_actions()?.into_iter().map(|action|action.domain).collect()))))
    }
    pub fn contains(&self,domain:&str)->bool {
        self.0.read().unwrap_or_else(|poisoned|poisoned.into_inner()).contains(domain)
    }
    pub fn insert(&self,domain:String) {
        self.0.write().unwrap_or_else(|poisoned|poisoned.into_inner()).insert(domain);
    }
    pub fn remove(&self,domain:&str) {
        self.0.write().unwrap_or_else(|poisoned|poisoned.into_inner()).remove(domain);
    }
}


/// Full lookup that hits SQLite when the cache has no entry (async to avoid blocking executor).
pub async fn get_action_for_domain_db(domain: &str, db: &Arc<AnalyticsDb>) -> Option<CustomAction> {
    if let Some(cached) = cache().get(domain) {
        return cached;
    }
    let domain_clone = domain.to_string();
    let db_clone = db.clone();
    let result = tokio::task::spawn_blocking(move || {
        db_clone.get_action(&domain_clone)
    }).await.unwrap_or(None);
    cache().insert(domain.to_string(), result.clone());
    result
}

/// Invalidate a single domain from the cache (call after any write).
pub fn invalidate(domain: &str) {
    cache().invalidate(domain);
}

/// Hash a raw action token with SHA-256. Store the returned hex string in the DB, never the raw token.
pub(crate) fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

pub fn hash_token(raw: &str) -> String {
    let digest = Sha256::digest(raw.as_bytes());
    encode_hex(&digest)
}

/// Constant-time comparison of a raw token against a stored SHA-256 hash.
pub fn verify_token(raw: &str, stored_hash: &str) -> bool {
    use subtle::ConstantTimeEq;
    let computed = hash_token(raw);
    computed.as_bytes().ct_eq(stored_hash.as_bytes()).into()
}


/// The admin must explicitly permit each executable in the service environment.
/// Legacy shell strings are rejected, never reinterpreted by a shell.
fn executable_args(command: &str) -> anyhow::Result<Vec<String>> {
    let args: Vec<String> = serde_json::from_str(command).map_err(|_| anyhow::anyhow!("Command must be a fixed JSON argument array, e.g. [\"/usr/local/bin/job\",\"--quiet\"]"))?;
    let executable = args.first().ok_or_else(||anyhow::anyhow!("Missing executable"))?;
    anyhow::ensure!(args.len() <= 64 && args.iter().all(|s|s.len() <= 4096),"Action arguments too large");
    anyhow::ensure!(std::path::Path::new(executable).is_absolute() && !executable.contains('{'),"Executable must be a fixed absolute path");
    // A token holder controls request parameters. Substituting those values
    // into argv is unsafe even without a shell: an allowlisted interpreter can
    // deliberately treat one argv element as program text (`sh -c`,
    // `python -c`, and similar modes). Executable actions are therefore
    // trigger-only with administrator-defined, fixed arguments.
    anyhow::ensure!(
        args.iter().skip(1).all(|arg| !arg.contains('{') && !arg.contains('}')),
        "Executable action arguments must be fixed; request placeholders are not supported",
    );
    let allowed = std::env::var("AEGIS_ACTION_EXECUTABLES").unwrap_or_default();
    anyhow::ensure!(allowed.split(':').any(|path|path == executable),"Executable is not in AEGIS_ACTION_EXECUTABLES; shell actions are disabled by default");
    Ok(args)
}

#[cfg(unix)]
async fn terminate_process_group(pid: u32) {
    let Ok(pid) = i32::try_from(pid) else { return; };
    // SAFETY: a negative PID addresses the process group created in pre_exec.
    // Signals are best-effort because the direct child may already have exited.
    unsafe { libc::kill(-pid, libc::SIGTERM); }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // A descendant may ignore SIGTERM. SIGKILL closes the lifecycle boundary.
    unsafe { libc::kill(-pid, libc::SIGKILL); }
}

#[cfg(not(unix))]
async fn terminate_process_group(_pid: u32) {
    // validate() rejects executable actions on platforms where AegisDNS cannot
    // enforce a process-tree lifetime. This definition keeps the shared match
    // arm type-checkable without creating an unsafe compatibility fallback.
}

pub fn validate(kind: &str, command: Option<&str>, url: Option<&str>, method: Option<&str>, token: Option<&str>) -> anyhow::Result<()> {
    anyhow::ensure!(token.is_some_and(|s|s.len() >= 32 && s.len() <= 256),"Action token must contain 32–256 characters");
    match kind {
        "shell" => {
            #[cfg(not(unix))]
            anyhow::bail!("Executable actions require Unix process-group isolation");
            #[cfg(unix)]
            executable_args(command.unwrap_or(""))?;
        }
        "webhook" => {
            let url = reqwest::Url::parse(url.unwrap_or(""))?;
            anyhow::ensure!(url.scheme() == "https" && url.host_str().is_some() && url.username().is_empty() && url.password().is_none() && !url.as_str().contains(['{','}']),"Webhook requires a fixed HTTPS URL; parameters are sent as JSON");
            anyhow::ensure!(matches!(url.port(), None | Some(443)), "Webhook HTTPS URLs must use port 443");
            if let Some(host) = url.host_str() {
                if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                    anyhow::ensure!(!config::is_internal_address(ip), "Webhook address must be public");
                }
            }
            anyhow::ensure!(matches!(method.unwrap_or("POST").to_ascii_uppercase().as_str(), "GET" | "POST"), "Webhook method must be GET or POST");
        }
        "html" => (), _ => anyhow::bail!("Unsupported action type"),
    }
    Ok(())
}

pub async fn execute(action: &CustomAction, params: &std::collections::HashMap<String,String>, provided_token: &str) -> anyhow::Result<String> {
    // Verify the provided token against the stored SHA-256 hash using constant-time comparison.
    let stored_hash = action.token.as_deref().unwrap_or("");
    anyhow::ensure!(!stored_hash.is_empty() && verify_token(provided_token, stored_hash), "Invalid action token");
    validate(&action.action_type,action.shell_command.as_deref(),action.payload_url.as_deref(),action.method.as_deref(),Some(provided_token))?;
    anyhow::ensure!(params.len() <= 32 && params.iter().all(|(k,v)|k.len() <= 64 && v.len() <= 4096),"Too many or oversized parameters");
    match action.action_type.as_str() {
        "shell" => {
            let args = executable_args(action.shell_command.as_deref().unwrap_or(""))?;
            let mut cmd = tokio::process::Command::new(&args[0]);
            cmd.args(&args[1..])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .kill_on_drop(true)
                // Sandbox: clear inherited environment so secrets like tokens,
                // database paths, and internal config cannot leak to the child.
                .env_clear()
                // Provide only the minimal, safe environment variables the child needs.
                .env("PATH", "/usr/local/bin:/usr/bin:/bin")
                .env("HOME", "/tmp")
                .env("LANG", "C.UTF-8")
                // Confine the working directory to a non-sensitive location.
                .current_dir("/tmp");
            // On Unix, drop the child into its own process group so it cannot
            // signal the parent DNS server, and set a conservative umask.
            #[cfg(unix)]
            {
                // SAFETY: setpgid and umask are async-signal-safe.
                unsafe { cmd.pre_exec(|| { libc::setpgid(0, 0); libc::umask(0o077); Ok(()) }); }
            }
            let mut child = cmd.spawn()?;
            let pid = child.id().ok_or_else(|| anyhow::anyhow!("Action process has no PID"))?;
            let status = match tokio::time::timeout(Duration::from_secs(15), child.wait()).await {
                Ok(Ok(status)) => {
                    // The direct child can exit after daemonizing descendants.
                    // Always close the entire group before releasing the action
                    // request's concurrency permit.
                    terminate_process_group(pid).await;
                    status
                }
                Ok(Err(error)) => {
                    terminate_process_group(pid).await;
                    return Err(error.into());
                }
                Err(_) => {
                    terminate_process_group(pid).await;
                    let _ = tokio::time::timeout(Duration::from_secs(2), child.wait()).await;
                    anyhow::bail!("Action exceeded the 15-second time limit");
                }
            };
            anyhow::ensure!(status.success(),"Action exited unsuccessfully");
        }
        "webhook" => {
            let url = reqwest::Url::parse(action.payload_url.as_deref().unwrap_or(""))?;
            let host = url.host_str().ok_or_else(|| anyhow::anyhow!("Webhook host is missing"))?.to_string();
            let port = url.port_or_known_default().ok_or_else(|| anyhow::anyhow!("Webhook port is missing"))?;
            let addresses: Vec<std::net::SocketAddr> = tokio::time::timeout(
                Duration::from_secs(5),
                tokio::net::lookup_host((host.as_str(), port)),
            ).await.map_err(|_|anyhow::anyhow!("Webhook DNS lookup timed out"))??.collect();
            anyhow::ensure!(!addresses.is_empty(), "Webhook host did not resolve");
            anyhow::ensure!(addresses.iter().all(|addr| !config::is_internal_address(addr.ip())), "Webhook host resolves to a private, local, or special-use address");
            // Pin the checked address so a second DNS lookup cannot rebind the request.
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .redirect(reqwest::redirect::Policy::none())
                .no_proxy()
                .resolve(&host, addresses[0])
                .build()?;
            // Reuse the already-parsed URL rather than unwrapping the option a
            // second time; the parse above is the single point of validation.
            let req = if action.method.as_deref().is_some_and(|m| m.eq_ignore_ascii_case("GET")) { client.get(url).query(params) }
                else { client.post(url).json(params) };
            req.send().await?.error_for_status()?;
        }
        "html" => return Ok(action.html_content.clone().unwrap_or_default()),
        // validate() above rejects any other type, so this is defence in
        // depth. Return an error rather than unreachable!(): a future action
        // type added to validate() but not here would otherwise panic the
        // request handler instead of reporting an unsupported action.
        other => anyhow::bail!("Unsupported action type: {other}"),
    }
    Ok(config::html_escape(action.success_msg.as_deref().unwrap_or("Action completed")))
}

#[cfg(test)] mod tests {
    #[test] fn hashes_tokens_as_lowercase_sha256_hex() {
        assert_eq!(
            super::hash_token("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
    }

    #[test] fn reject_legacy_shell_and_unauthenticated_actions() {
        assert!(super::validate("shell",Some("echo {value}"),None,None,Some(&"x".repeat(32))).is_err());
        // Request values must never become argv for a general-purpose
        // executable. An allowlisted interpreter would otherwise turn a
        // seemingly safe whole-argument placeholder into program text.
        std::env::set_var("AEGIS_ACTION_EXECUTABLES", "/bin/sh");
        assert!(super::validate(
            "shell",
            Some(r#"["/bin/sh","-c","{value}"]"#),
            None,
            None,
            Some(&"x".repeat(32)),
        ).is_err());
        std::env::remove_var("AEGIS_ACTION_EXECUTABLES");
        assert!(super::validate("html",None,None,None,None).is_err());
        assert!(super::validate("webhook",None,Some("http://example.com"),Some("POST"),Some(&"x".repeat(32))).is_err());
        assert!(super::validate("webhook",None,Some("https://127.0.0.1/hook"),Some("POST"),Some(&"x".repeat(32))).is_err());
        assert!(super::validate("webhook",None,Some("https://example.com/hook"),Some("DELETE"),Some(&"x".repeat(32))).is_err());
        assert!(super::validate("webhook",None,Some("https://example.com:8443/hook"),Some("POST"),Some(&"x".repeat(32))).is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn process_group_cleanup_terminates_background_descendants() {
        let mut command=tokio::process::Command::new("/bin/sh");
        command.args(["-c","sleep 30 & wait"]).kill_on_drop(true);
        unsafe { command.pre_exec(|| { libc::setpgid(0,0); Ok(()) }); }
        let mut child=command.spawn().unwrap();
        let pid=child.id().unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        super::terminate_process_group(pid).await;
        tokio::time::timeout(std::time::Duration::from_secs(2),child.wait()).await.unwrap().unwrap();
        let group=i32::try_from(pid).unwrap();
        assert_ne!(unsafe { libc::kill(-group,0) },0,"no action descendant may survive cleanup");
    }
}
