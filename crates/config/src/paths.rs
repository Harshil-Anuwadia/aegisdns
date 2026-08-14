use std::path::PathBuf;

pub fn get_data_dir() -> PathBuf {
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
