use std::collections::HashMap;
use std::net::{Ipv4Addr, UdpSocket};
use std::ops::Add;
use std::sync::Arc;
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

pub fn load_config() -> DhcpConfig {
    let path = config_path();
    if path.exists() {
        if let Ok(data) = std::fs::read_to_string(&path) {
            if let Ok(cfg) = serde_json::from_str(&data) {
                return cfg;
            }
        }
    }
    DhcpConfig::default()
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
}

impl AegisDhcpServer {
    pub fn new(config: DhcpConfig, device_registry: Arc<RwLock<DeviceRegistry>>, rt: tokio::runtime::Handle) -> Self {
        Self {
            config,
            leases: load_leases(),
            last_lease: 0,
            device_registry,
            rt,
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
        let num_leases = end_num - start_num + 1;
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
                
                if let Err(e)=save_leases(&self.leases) {error!("DHCP lease persistence failed: {}",e); return;}
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
                    if let Err(e)=save_leases(&self.leases) {error!("DHCP lease persistence failed: {}",e);}
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
#[derive(Serialize,Deserialize)]
struct SavedLease {ip:Ipv4Addr,mac:[u8;6],expires:u64}
fn lease_path()->PathBuf {config::paths::get_data_dir().join("dhcp-leases.json")}
fn load_leases()->HashMap<Ipv4Addr,([u8;6],Instant)> {
    let now=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs();
    std::fs::read(lease_path()).ok().and_then(|b|serde_json::from_slice::<Vec<SavedLease>>(&b).ok()).unwrap_or_default().into_iter()
        .filter(|l|l.expires>now && l.expires-now<=30*86400).map(|l|(l.ip,(l.mac,Instant::now()+Duration::from_secs(l.expires-now)))).collect()
}
fn save_leases(leases:&HashMap<Ipv4Addr,([u8;6],Instant)>)->anyhow::Result<()> {
    let now=Instant::now(); let unix=std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_secs();
    let leases:Vec<_>=leases.iter().filter(|(_,(_,end))|*end>now).map(|(ip,(mac,end))|SavedLease{ip:*ip,mac:*mac,expires:unix+end.duration_since(now).as_secs()}).collect();
    config::atomic_write(lease_path(),serde_json::to_vec(&leases)?)?; Ok(())
}
#[cfg(test)] mod tests {
    use super::*;
    #[test] fn pool_validation() {
        assert!(validate_config(&DhcpConfig::default()).is_ok());
        let mut c=DhcpConfig::default();c.end_ip="192.168.1.20".into();assert!(validate_config(&c).is_err());
        c=DhcpConfig::default();c.subnet_mask="255.0.255.0".into();assert!(validate_config(&c).is_err());
    }
    #[tokio::test] async fn runtime_handle_is_movable_to_worker() {
        let handle=tokio::runtime::Handle::current();
        assert!(std::thread::spawn(move||handle.spawn(async{42})).join().unwrap().await.is_ok());
    }
}
