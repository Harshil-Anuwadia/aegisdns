use anyhow::Result;
use std::{sync::Arc, collections::HashMap, path::PathBuf};
use tokio::{net::{UdpSocket,TcpListener},sync::RwLock, io::{AsyncReadExt,AsyncWriteExt}};
use hickory_proto::{op::ResponseCode,rr::RecordType};

#[derive(Debug,Clone,serde::Serialize,serde::Deserialize,Default)]
pub struct OpenRootZone {pub a_records:HashMap<String,String>}
impl OpenRootZone {
    fn parse(bytes:&[u8])->Result<Self> {
        let zone:Self=serde_json::from_slice(bytes)?;
        let mut normalized=HashMap::new();
        for (name,ip) in zone.a_records {
            let name=config::canonical_domain(&name);
            anyhow::ensure!(config::valid_domain(&name) && config::dns::local_zone(&name),"Invalid local zone name: {}",name);
            let ip:std::net::Ipv4Addr=ip.parse()?;
            normalized.insert(name,ip.to_string());
        }
        Ok(Self{a_records:normalized})
    }
}
pub struct OpenRootServer {pub zone:Arc<RwLock<OpenRootZone>>,pub config_path:PathBuf}
impl OpenRootServer {
    pub fn new()->Self {Self{zone:Default::default(),config_path:config::paths::get_data_dir().join("openroot.json")}}
    pub async fn load_zones(&self)->Result<()> {
        match tokio::fs::read(&self.config_path).await {
            Ok(bytes)=>{*self.zone.write().await=OpenRootZone::parse(&bytes)?;}
            Err(e) if e.kind()==std::io::ErrorKind::NotFound=>{
                // Seed an empty zone file when the filesystem allows it, but
                // never treat failure as fatal. The supplied Compose service
                // runs read_only with openroot.json mounted :ro, so a missing
                // file previously stopped the server from starting at all.
                // An empty in-memory zone is a valid state: every local-zone
                // query simply answers NXDOMAIN.
                if let Err(write_error)=config::atomic_write(&self.config_path,b"{\"a_records\":{}}") {
                    tracing::warn!(
                        "Serving an empty local zone: {} is missing and could not be created ({write_error})",
                        self.config_path.display()
                    );
                }
            }
            Err(e)=>return Err(e.into()),
        }
        Ok(())
    }
    pub async fn start(&self,addr:&str)->Result<()> {
        self.load_zones().await?;
        let udp=UdpSocket::bind(addr).await?;
        let tcp=TcpListener::bind(addr).await?;
        let zone=self.zone.clone(); let path=self.config_path.clone();
        let mut tasks=tokio::task::JoinSet::new();
        tasks.spawn(async move {
            let mut previous=Vec::new();
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(10)).await;
                if let Ok(bytes)=tokio::fs::read(&path).await {
                    if bytes!=previous {
                        match OpenRootZone::parse(&bytes) {
                            Ok(next)=>{*zone.write().await=next;previous=bytes;}
                            Err(e)=>tracing::error!("Zone reload rejected; retaining current records: {}",e),
                        }
                    }
                }
            }
        });
        let zone=self.zone.clone();
        tasks.spawn(async move {
            let mut buf=vec![0;65535];
            loop {
                let Ok((n,src))=udp.recv_from(&mut buf).await else {break;};
                if let Some(resp)=Self::handle_query(&buf[..n],&zone,false).await {let _=udp.send_to(&resp,src).await;}
            }
        });
        let zone=self.zone.clone();
        tasks.spawn(async move {
            let limits=Arc::new(tokio::sync::Semaphore::new(64));
            let mut clients=tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    biased;
                    Some(_)=clients.join_next(), if !clients.is_empty()=>{},
                    accepted=tcp.accept()=>{
                        let Ok((mut stream,_))=accepted else {break;};
                        let Ok(permit)=limits.clone().try_acquire_owned() else {continue;};
                        let zone=zone.clone();
                        clients.spawn(async move {
                            let _permit=permit;
                            let _=tokio::time::timeout(std::time::Duration::from_secs(15),async {
                                loop {
                                    let Ok(n)=stream.read_u16().await else {break;};
                                    if n<12 {break;}
                                    let mut bytes=vec![0;n as usize];
                                    if stream.read_exact(&mut bytes).await.is_err(){break;}
                                    let Some(resp)=Self::handle_query(&bytes,&zone,true).await else {break;};
                                    if stream.write_u16(resp.len() as u16).await.is_err() || stream.write_all(&resp).await.is_err(){break;}
                                }
                            }).await;
                        });
                    }
                }
            }
        });
        let result=tasks.join_next().await;
        anyhow::bail!("OpenRoot listener exited unexpectedly: {:?}",result)
    }
    async fn handle_query(bytes:&[u8],zone:&Arc<RwLock<OpenRootZone>>,tcp:bool)->Option<Vec<u8>> {
        let q=config::dns::parse_query(bytes)?;
        let name=config::canonical_domain(&q.queries[0].name.to_ascii());
        let z=zone.read().await;
        let mut response=if !config::dns::local_zone(&name) {config::dns::reply(&q,ResponseCode::Refused)}
        else if let Some(ip)=z.a_records.get(&name) {
            if q.queries[0].query_type==RecordType::A {config::dns::ipv4_reply(&q,ip.parse().ok()?)}
            else {config::dns::negative(&q,ResponseCode::NoError)}
        } else if z.a_records.keys().any(|entry|entry.ends_with(&format!(".{name}"))) {
            config::dns::negative(&q,ResponseCode::NoError) // Existing empty nonterminal.
        } else {config::dns::negative(&q,ResponseCode::NXDomain)};
        response.metadata.authoritative=true; response.metadata.recursion_available=false;
        config::dns::encode_for_client(&response,&q,tcp)
    }
}
#[tokio::main]
async fn main()->Result<()> {
    tracing_subscriber::fmt().with_target(false).init();
    OpenRootServer::new().start(&config::paths::get_openroot_addr()).await
}
#[cfg(test)] mod tests {
    use super::*;
    use hickory_proto::op::Message;
    use hickory_proto::{op::Query,rr::Name};
    #[tokio::test] async fn aaaa_for_existing_name_is_nodata() {
        let zone=Arc::new(RwLock::new(OpenRootZone{a_records:HashMap::from([("router.lan".into(),"192.168.1.1".into())])}));
        let mut q=Message::query(); q.add_query(Query::query(Name::from_ascii("ROUTER.LAN").unwrap(),RecordType::AAAA));
        let r=Message::from_vec(&OpenRootServer::handle_query(&q.to_vec().unwrap(),&zone,false).await.unwrap()).unwrap();
        assert_eq!(r.metadata.response_code,ResponseCode::NoError); assert!(r.answers.is_empty()); assert_eq!(r.authorities.len(),1);
        q.queries[0].name=Name::from_ascii("missing.lan").unwrap();
        let r=Message::from_vec(&OpenRootServer::handle_query(&q.to_vec().unwrap(),&zone,false).await.unwrap()).unwrap();
        assert_eq!(r.metadata.response_code,ResponseCode::NXDomain);
    }
    #[test] fn invalid_zone_rejected() {assert!(OpenRootZone::parse(br#"{"a_records":{"router.lan":"not-an-ip"}}"#).is_err());}
}
