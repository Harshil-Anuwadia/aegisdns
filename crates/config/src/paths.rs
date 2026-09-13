use std::path::PathBuf;

pub fn get_data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("AEGIS_DATA_DIR") { return PathBuf::from(dir); }
    #[cfg(unix)]
    {
        PathBuf::from("/var/lib/aegisdns")
    }
    #[cfg(windows)]
    {
        let mut path = PathBuf::from(std::env::var("ProgramData").unwrap_or_else(|_| "C:\\ProgramData".into()));
        path.push("AegisDNS");
        path
    }
}

pub fn get_policy_path() -> PathBuf {
    get_data_dir().join("policy.json")
}

pub fn get_db_path() -> PathBuf {
    get_data_dir().join("analytics.db")
}

/// Address of the authoritative local-zone (OpenRoot) server.
///
/// Shared so the OpenRoot binary and the proxy that forwards local-zone
/// queries to it cannot drift apart: both used to hardcode this string
/// separately, and changing one without the other silently broke local-zone
/// resolution. Override with `AEGIS_OPENROOT_ADDR`.
pub fn get_openroot_addr() -> String {
    match std::env::var("AEGIS_OPENROOT_ADDR") {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => "127.0.0.1:5354".to_string(),
    }
}

pub fn get_ipc_path() -> String {
    #[cfg(unix)]
    {
        "/run/aegisdns/aegis.sock".to_string()
    }
    #[cfg(windows)]
    {
        "127.0.0.1:5382".to_string()
    }
}
