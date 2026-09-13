use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::ops::Add;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use dhcp4r::{options, packet, server};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, error};
use std::path::PathBuf;

use crate::device_registry::DeviceRegistry;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpConfig {
    pub enabled: bool,
    pub server_ip: String,
    pub router_ip: String,
    pub subnet_mask: String,
    pub start_ip: String,
    pub end_ip: String,
    pub lease_duration_secs: u32,
}

impl Default for DhcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            server_ip: "192.168.1.1".into(),
            router_ip: "192.168.1.1".into(),
            subnet_mask: "255.255.255.0".into(),
            start_ip: "192.168.1.100".into(),
            end_ip: "192.168.1.200".into(),
            lease_duration_secs: 43200, // 12 hours
        }
    }
}

pub fn config_path() -> PathBuf {
    config::paths::get_data_dir().join("dhcp.json")
}

/// Read `dhcp.json`, falling back to the (disabled) default on any problem.
///
/// The stored file is validated exactly like one submitted through the API.
/// `save_config` has always validated, but a hand-edited or partially written
/// file used to be trusted verbatim — an inverted pool (`end_ip` below
/// `start_ip`) then underflowed the lease-count arithmetic and panicked the
/// DHCP thread on the first packet.
pub fn load_config() -> DhcpConfig {
    let path = config_path();
    if !path.exists() {
        return DhcpConfig::default();
    }
    let cfg: DhcpConfig = match std::fs::read_to_string(&path) {
        Ok(data) => match serde_json::from_str(&data) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("Ignoring dhcp.json: {e}");
                return DhcpConfig::default();
            }
        },
        Err(e) => {
            error!("Cannot read dhcp.json: {e}");
            return DhcpConfig::default();
        }
    };
    // A disabled server never binds a socket, so its pool is irrelevant.
    if cfg.enabled {
        if let Err(e) = validate_config(&cfg) {
            error!("Refusing to start DHCP with invalid dhcp.json: {e}");
            return DhcpConfig::default();
        }
    }
    cfg
}

pub fn save_config(cfg: &DhcpConfig) -> Result<(), String> {
    validate_config(cfg)?;
    let data = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    config::atomic_write(config_path(), data).map_err(|e| e.to_string())?;
    Ok(())
}

// In-memory DHCP Server state
pub struct AegisDhcpServer {
    config: DhcpConfig,
    leases: HashMap<Ipv4Addr, ([u8; 6], Instant)>,
    last_lease: u32,
    device_registry: Arc<RwLock<DeviceRegistry>>,
    rt: tokio::runtime::Handle,
    lease_persister: LeasePersister,
}

impl AegisDhcpServer {
    pub fn new(config: DhcpConfig, device_registry: Arc<RwLock<DeviceRegistry>>, rt: tokio::runtime::Handle) -> Self {
        Self {
            config,
            leases: load_leases(),
            last_lease: 0,
            device_registry,
            rt,
            lease_persister: LeasePersister::new(),
        }
    }

    fn available(&self, chaddr: &[u8; 6], addr: &Ipv4Addr, start: u32, num_leases: u32) -> bool {
        let pos: u32 = (*addr).into();
        pos >= start && pos < start.saturating_add(num_leases) && match self.leases.get(addr) {
            Some(x) => x.0 == *chaddr || Instant::now().gt(&x.1),
            None => true,
        }
    }

    fn current_lease(&self, chaddr: &[u8; 6]) -> Option<Ipv4Addr> {
        for (i, v) in &self.leases {
            if &v.0 == chaddr && Instant::now() < v.1 {
                return Some(*i);
            }
        }
        None
    }
}

impl server::Handler for AegisDhcpServer {
    fn handle_request(&mut self, server: &server::Server, in_packet: packet::Packet) {
        let start_ip: Ipv4Addr = self.config.start_ip.parse().unwrap_or(Ipv4Addr::new(192,168,1,100));
        let end_ip: Ipv4Addr = self.config.end_ip.parse().unwrap_or(Ipv4Addr::new(192,168,1,200));
        let start_num: u32 = start_ip.into();
        let end_num: u32 = end_ip.into();
        // Defence in depth: load_config() rejects an inverted pool, but this
        // subtraction runs on every packet and must never underflow.
        let Some(num_leases) = end_num.checked_sub(start_num).and_then(|n| n.checked_add(1)) else {
            error!("DHCP pool {start_ip}-{end_ip} is inverted; ignoring request");
            return;
        };
        let server_ip: Ipv4Addr = self.config.server_ip.parse().unwrap_or(Ipv4Addr::new(192,168,1,1));
        let subnet_mask: Ipv4Addr = self.config.subnet_mask.parse().unwrap_or(Ipv4Addr::new(255,255,255,0));
        let router_ip: Ipv4Addr = self.config.router_ip.parse().unwrap_or(Ipv4Addr::new(192,168,1,1));
        
        let msg_type = match in_packet.message_type() {
            Ok(m) => m,
            Err(_) => return,
        };

        match msg_type {
            options::MessageType::Discover => {
                let req_ip_opt = match in_packet.option(options::REQUESTED_IP_ADDRESS) {
                    Some(options::DhcpOption::RequestedIpAddress(addr)) => Some(*addr),
                    _ => None,
                };
                
                if let Some(addr) = req_ip_opt {
                    if self.available(&in_packet.chaddr, &addr, start_num, num_leases) {
                        reply(server, options::MessageType::Offer, in_packet, &addr, self.config.lease_duration_secs, subnet_mask, router_ip, server_ip);
                        return;
                    }
                }
                if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                    reply(server, options::MessageType::Offer, in_packet, &ip, self.config.lease_duration_secs, subnet_mask, router_ip, server_ip);
                    return;
                }
                for _ in 0..num_leases {
                    self.last_lease = (self.last_lease + 1) % num_leases;
                    let candidate: Ipv4Addr = (start_num + self.last_lease).into();
                    if self.available(&in_packet.chaddr, &candidate, start_num, num_leases) {
                        reply(server, options::MessageType::Offer, in_packet, &candidate, self.config.lease_duration_secs, subnet_mask, router_ip, server_ip);
                        break;
                    }
                }
            }
            options::MessageType::Request => {
                if !server.for_this_server(&in_packet) {
                    return;
                }
                let req_ip = match in_packet.option(options::REQUESTED_IP_ADDRESS) {
                    Some(options::DhcpOption::RequestedIpAddress(x)) => *x,
                    _ => in_packet.ciaddr,
                };
                if !self.available(&in_packet.chaddr, &req_ip, start_num, num_leases) {
                    nak(server, in_packet, "Requested IP not available");
                    return;
                }
                
                self.leases.insert(req_ip, (in_packet.chaddr, Instant::now().add(Duration::from_secs(self.config.lease_duration_secs as u64))));
                
                self.lease_persister.schedule(&self.leases);
                // Extract Hostname and auto-register in AegisDNS!
                let hostname_opt = match in_packet.option(options::HOST_NAME) {
                    Some(options::DhcpOption::HostName(name)) => Some(name.clone()),
                    _ => None,
                };
                
                if let Some(hostname) = hostname_opt {
                    let ip_str = req_ip.to_string();
                    let reg = self.device_registry.clone();
                    self.rt.spawn(async move {
                        let mut r = reg.write().await;
                        let _ = r.add_device(ip_str, hostname);
                    });
                }
                
                reply(server, options::MessageType::Ack, in_packet, &req_ip, self.config.lease_duration_secs, subnet_mask, router_ip, server_ip);
            }
            options::MessageType::Release | options::MessageType::Decline => {
                if !server.for_this_server(&in_packet) {
                    return;
                }
                if let Some(ip) = self.current_lease(&in_packet.chaddr) {
                    self.leases.remove(&ip);
                    self.lease_persister.schedule(&self.leases);
                }
            }
            _ => {}
        }
    }
}

fn reply(s: &server::Server, msg_type: options::MessageType, req_packet: packet::Packet, offer_ip: &Ipv4Addr, lease_secs: u32, subnet: Ipv4Addr, router: Ipv4Addr, dns: Ipv4Addr) {
    let _ = s.reply(
        msg_type,
        vec![
            options::DhcpOption::IpAddressLeaseTime(lease_secs),
            options::DhcpOption::SubnetMask(subnet),
            options::DhcpOption::Router(vec![router]),
            options::DhcpOption::DomainNameServer(vec![dns]), // AegisDNS sets itself as DNS!
        ],
        *offer_ip,
        req_packet,
    );
}

fn nak(s: &server::Server, req_packet: packet::Packet, message: &str) {
    let _ = s.reply(
        options::MessageType::Nak,
        vec![options::DhcpOption::Message(message.to_string())],
        Ipv4Addr::new(0, 0, 0, 0),
        req_packet,
    );
}

pub fn start_dhcp_server(config: DhcpConfig, device_registry: Arc<RwLock<DeviceRegistry>>) {
    if !config.enabled {
        return;
    }
    let server_ip: Ipv4Addr = config.server_ip.parse().unwrap_or(Ipv4Addr::new(192,168,1,1));
    if let Err(e)=validate_config(&config) { error!("DHCP configuration rejected: {}",e); return; }
    let rt = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        match UdpSocket::bind("0.0.0.0:67") {
            Ok(socket) => {
                let _ = socket.set_broadcast(true);
                info!("DHCP Server started on 0.0.0.0:67 (Server IP: {})", server_ip);
                let handler = AegisDhcpServer::new(config, device_registry, rt);
                server::Server::serve(socket, server_ip, handler);
            }
            Err(e) => {
                error!("Failed to bind DHCP socket on port 67: {}. (Are you running as root?)", e);
            }
        }
    });
}

pub fn validate_config(c:&DhcpConfig)->Result<(),String> {
    let parse=|v:&str|v.parse::<Ipv4Addr>().map(u32::from).map_err(|_|format!("Invalid IPv4 address: {}",v));
    let (start,end,server,router,mask)=(parse(&c.start_ip)?,parse(&c.end_ip)?,parse(&c.server_ip)?,parse(&c.router_ip)?,parse(&c.subnet_mask)?);
    if start>end || end-start>65535 || mask==0 || (!mask).checked_add(1).is_none_or(|v|v & !mask != 0)
        || start & mask != server & mask || end & mask != server & mask || router & mask != server & mask
        || start & !mask == 0 || end & !mask == !mask || (start..=end).contains(&server) || (start..=end).contains(&router)
        || c.lease_duration_secs<60 || c.lease_duration_secs>30*86400 {return Err("Invalid DHCP pool, mask, reserved address, or lease duration".into());}
    Ok(())
}
#[derive(Clone,Serialize,Deserialize)]
struct SavedLease {ip:Ipv4Addr,mac:[u8;6],expires:u64}
fn lease_path()->PathBuf {config::paths::get_data_dir().join("dhcp-leases.json")}
fn load_leases()->HashMap<Ipv4Addr,([u8;6],Instant)> {
    let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    std::fs::read(lease_path()).ok().and_then(|b|serde_json::from_slice::<Vec<SavedLease>>(&b).ok()).unwrap_or_default().into_iter()
        .filter(|l|l.expires>now && l.expires-now<=30*86400).map(|l|(l.ip,(l.mac,Instant::now()+Duration::from_secs(l.expires-now)))).collect()
}
fn lease_snapshot(leases:&HashMap<Ipv4Addr,([u8;6],Instant)>)->Vec<SavedLease> {
    let now=Instant::now(); let unix=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    leases.iter().filter(|(_,(_,end))|*end>now).map(|(ip,(mac,end))|SavedLease{ip:*ip,mac:*mac,expires:unix+end.duration_since(now).as_secs()}).collect()
}

#[derive(Clone)]
struct LeasePersister {
    pending: Arc<(Mutex<Option<Vec<SavedLease>>>, Condvar)>,
}

impl LeasePersister {
    fn new() -> Self {
        let pending = Arc::new((Mutex::new(None::<Vec<SavedLease>>), Condvar::new()));
        let worker = pending.clone();
        std::thread::Builder::new().name("aegisdns-dhcp-persist".into()).spawn(move || loop {
            let leases = {
                let (lock, ready) = &*worker;
                let mut value = lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                while value.is_none() {
                    value = ready.wait(value).unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                value.take().unwrap_or_default()
            };
            let result = (|| -> anyhow::Result<()> {
                config::atomic_write(lease_path(), serde_json::to_vec(&leases)?)?;
                Ok(())
            })();
            match result {
                Ok(()) => {}
                Err(err) => error!("DHCP lease persistence failed: {}", err),
            }
        }).expect("failed to start DHCP lease persistence worker");
        Self { pending }
    }

    fn schedule(&self, leases: &HashMap<Ipv4Addr, ([u8; 6], Instant)>) {
        let snapshot = lease_snapshot(leases);
        let (lock, ready) = &*self.pending;
        *lock.lock().unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(snapshot);
        ready.notify_one();
    }
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn pool_validation() {
        assert!(validate_config(&DhcpConfig::default()).is_ok());
        let mut c=DhcpConfig::default();c.end_ip="192.168.1.20".into();assert!(validate_config(&c).is_err());
        c=DhcpConfig::default();c.subnet_mask="255.0.255.0".into();assert!(validate_config(&c).is_err());
    }
    /// An inverted pool must be rejected rather than reaching the lease
    /// arithmetic, where `end - start + 1` would underflow and panic.
    #[test] fn inverted_pool_is_rejected() {
        let mut c=DhcpConfig::default();
        c.start_ip="192.168.1.200".into();
        c.end_ip="192.168.1.100".into();
        assert!(validate_config(&c).is_err(),"end_ip below start_ip must not validate");
    }

    /// A disabled server is loadable regardless of its pool, but an enabled
    /// server with an invalid pool must fall back to the safe default.
    #[test] fn invalid_enabled_config_falls_back_to_disabled_default() {
        let mut c=DhcpConfig::default();
        c.enabled=true;
        c.start_ip="192.168.1.200".into();
        c.end_ip="192.168.1.100".into();
        assert!(validate_config(&c).is_err());
        assert!(!DhcpConfig::default().enabled,"the fallback must not run a DHCP server");
    }

    #[tokio::test] async fn runtime_handle_is_movable_to_worker() {
        let handle=tokio::runtime::Handle::current();
        assert!(std::thread::spawn(move||handle.spawn(async{42})).join().unwrap().await.is_ok());
    }
}
