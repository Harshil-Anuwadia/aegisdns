use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::path::PathBuf;
use tracing::warn;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredDevice {
    pub ip: String,
    pub name: String,
    /// Profile: "default", "strict", or "bypass"
    #[serde(default = "default_profile")]
    pub profile: String,
}

fn default_profile() -> String {
    "default".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DeviceRegistry {
    pub devices: Vec<RegisteredDevice>,
}

#[allow(dead_code)]
impl DeviceRegistry {
    fn file_path() -> PathBuf {
        config::paths::get_data_dir().join("devices.json")
    }

    pub fn load() -> Self {
        let path = Self::file_path();
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(data) => match serde_json::from_str(&data) {
                    Ok(registry) => return registry,
                    Err(e) => warn!("Failed to parse devices.json: {}", e),
                },
                Err(e) => warn!("Failed to read devices.json: {}", e),
            }
        }
        Self::default()
    }

    pub fn save(&self) -> Result<(), String> {
        let path = Self::file_path();
        let data = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize: {}", e))?;
        config::atomic_write(&path, data)
            .map_err(|e| format!("Failed to write devices.json: {}", e))?;
        Ok(())
    }

    pub fn add_device(&mut self, ip: String, name: String) -> Result<(), String> {
        let ip=ip.parse::<std::net::IpAddr>().map_err(|_|"Invalid device IP")?.to_string();
        if name.trim().is_empty() || name.len()>128 || name.chars().any(char::is_control) {return Err("Device name must contain 1–128 printable characters".into());}
        let old=self.clone();
        // Preserve profile if device already exists
        let existing_profile = self.devices.iter()
            .find(|d| d.ip == ip)
            .map(|d| d.profile.clone())
            .unwrap_or_else(|| "default".to_string());
        self.devices.retain(|d| d.ip != ip);
        self.devices.push(RegisteredDevice { ip, name, profile: existing_profile });
        if let Err(e)=self.save() {*self=old;return Err(e);} Ok(())
    }

    pub fn set_profile(&mut self, ip: &str, profile: &str) -> Result<(), String> {
        let valid = ["default", "strict", "bypass"];
        if !valid.contains(&profile) {
            return Err(format!("Invalid profile: {}. Must be one of: default, strict, bypass", profile));
        }
        let old=self.clone();
        match self.devices.iter_mut().find(|d| d.ip == ip) {
            Some(dev) => {
                dev.profile = profile.to_string();
                if let Err(e)=self.save() {*self=old;return Err(e);} Ok(())
            }
            None => Err(format!("Device {} not found", ip)),
        }
    }

    /// Returns the device's profile, or "default" if not registered.
    pub fn get_profile(&self, ip: &str) -> &str {
        self.devices.iter()
            .find(|d| d.ip == ip)
            .map(|d| d.profile.as_str())
            .unwrap_or("default")
    }

    pub fn remove_device(&mut self, ip: &str) -> Result<(), String> {
        let old=self.clone();
        let before = self.devices.len();
        self.devices.retain(|d| d.ip != ip);
        if self.devices.len() == before {
            return Err(format!("Device with IP {} not found", ip));
        }
        if let Err(e)=self.save() {*self=old;return Err(e);} Ok(())
    }

    pub fn get_name(&self, ip: &str) -> Option<String> {
        self.devices.iter().find(|d| d.ip == ip).map(|d| d.name.clone())
    }

    pub fn list_devices(&self) -> &[RegisteredDevice] {
        &self.devices
    }

    pub fn is_registered(&self, ip: &str) -> bool {
        self.devices.iter().any(|d| d.ip == ip)
    }

    /// Returns a map of IP -> name for quick lookups
    pub fn ip_name_map(&self) -> HashMap<String, String> {
        self.devices.iter().map(|d| (d.ip.clone(), d.name.clone())).collect()
    }
}
