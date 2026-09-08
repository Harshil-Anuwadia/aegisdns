use super::*;
use hickory_proto::{op::Query,rr::{Name,Record,rdata::{A,CNAME}}};
use std::sync::atomic::{AtomicUsize,Ordering};

fn query(domain:&str)->Message {
    let mut q=Message::query();q.metadata.recursion_desired=true;
    q.add_query(Query::query(Name::from_ascii(domain).unwrap(),RecordType::A)); q
}
fn proxy(upstream:&str)->DnsProxy {
    let path=std::env::temp_dir().join(format!("aegis-proxy-{}-{}.db",std::process::id(),rand::random::<u64>()));
    DnsProxy::new("127.0.0.1:0",upstream,"127.0.0.1",Arc::new(AnalyticsDb::new(path).unwrap()),
        Arc::new(RwLock::new(PolicyEngine::new(policy::Profile::Balanced))),
        Arc::new(RwLock::new(BlocklistManager{lists:vec![],compiled_domains:Default::default(),compiled_exceptions:Default::default()})),
        Arc::new(RwLock::new(risk::FastFluxDetector::new())),Arc::new(AnomalyDetector::new()),Cache::new(1),
        Arc::new(RwLock::new(crate::telegram::TelegramConfig::default())),Arc::new(RwLock::new(crate::device_registry::DeviceRegistry::default())),
        Arc::new(RwLock::new(crate::upstream::UpstreamDnsConfig::default())))
}
#[tokio::test] async fn case_normalized_block_and_allow_override_strict() {
    let p=proxy("127.0.0.1:1");
    p.policy.write().await.deny("blocked.example".into());
    let q=query("BLOCKED.EXAMPLE");
    let r=Message::from_vec(&p.process(&q.to_vec().unwrap(),"192.168.1.3",false).await.unwrap()).unwrap();
    assert_eq!(r.metadata.response_code,ResponseCode::NXDomain);assert!(r.answers.is_empty());
    p.policy.write().await.allow("secure-login-verify.tk".into());
    p.device_registry.write().await.devices.push(crate::device_registry::RegisteredDevice{ip:"192.168.1.3".into(),name:"test".into(),profile:"strict".into()});
    assert!(matches!(p.decision("secure-login-verify.tk","192.168.1.3").await,PolicyDecision::Allowed(AllowReason::Explicit)));
}
#[tokio::test] async fn bypass_profile_has_consistent_cname_policy() {
    let p=proxy("127.0.0.1:1");p.policy.write().await.deny("tracker.example".into());
    p.device_registry.write().await.devices.push(crate::device_registry::RegisteredDevice{ip:"192.168.1.3".into(),name:"test".into(),profile:"bypass".into()});
    assert!(matches!(p.decision("tracker.example","192.168.1.3").await,PolicyDecision::Allowed(AllowReason::Bypass)));
}
#[tokio::test] async fn malformed_queries_are_rejected_without_panics() {
    let p=proxy("127.0.0.1:1");
    for n in 0..256 {let data=vec![0xff;n];assert!(p.process(&data,"192.168.1.3",false).await.is_none());}
    let mut q=query("example.com");q.add_query(q.queries[0].clone());assert!(p.process(&q.to_vec().unwrap(),"192.168.1.3",false).await.is_none());
}

#[tokio::test] async fn answer_inspection_applies_for_each_device_and_zero_ttl_is_not_cached() {
    let sock=UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr=sock.local_addr().unwrap().to_string();
    let seen=Arc::new(AtomicUsize::new(0));let count=seen.clone();
    let server=tokio::spawn(async move {
        let mut bytes=vec![0;4096];
        loop {
            let (n,src)=sock.recv_from(&mut bytes).await.unwrap();let q=Message::from_vec(&bytes[..n]).unwrap();
            count.fetch_add(1,Ordering::SeqCst);
            let mut r=dns::reply(&q,ResponseCode::NoError);
            r.add_answer(Record::from_rdata(q.queries[0].name.clone(),0,RData::CNAME(CNAME(Name::from_ascii("tracker.example").unwrap()))));
            r.add_answer(Record::from_rdata(Name::from_ascii("tracker.example").unwrap(),0,RData::A(A("8.8.8.8".parse().unwrap()))));
            sock.send_to(&r.to_vec().unwrap(),src).await.unwrap();
        }
    });
    let p=proxy(&addr);p.policy.write().await.deny_device("tracker.example".into(),"192.168.1.3".into());
    let q=query("alias.example").to_vec().unwrap();
    let a=Message::from_vec(&p.process(&q,"192.168.1.2",false).await.unwrap()).unwrap();
    assert_eq!(a.metadata.response_code,ResponseCode::NoError);assert_eq!(a.answers[0].ttl,0);
    let b=Message::from_vec(&p.process(&q,"192.168.1.3",false).await.unwrap()).unwrap();
    assert_eq!(b.metadata.response_code,ResponseCode::NXDomain);assert_eq!(seen.load(Ordering::SeqCst),2);
    server.abort();
}

#[tokio::test] async fn truncation_retries_tcp_and_rejects_wrong_question() {
    let tcp=TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=tcp.local_addr().unwrap();
    let udp=UdpSocket::bind(addr).await.unwrap();
    let upstream=tokio::spawn(async move {
        let mut buf=vec![0;4096];let (n,src)=udp.recv_from(&mut buf).await.unwrap();let q=Message::from_vec(&buf[..n]).unwrap();
        let mut invalid=dns::reply(&q,ResponseCode::NoError);invalid.queries[0].name=Name::from_ascii("wrong.example").unwrap();
        udp.send_to(&invalid.to_vec().unwrap(),src).await.unwrap();
        udp.send_to(&dns::reply(&q,ResponseCode::NoError).truncate().to_vec().unwrap(),src).await.unwrap();
        let (mut stream,_)=tcp.accept().await.unwrap();let request=Message::from_vec(&read_frame(&mut stream).await.unwrap()).unwrap();
        let answer=dns::ipv4_reply(&request,"8.8.4.4".parse().unwrap());write_frame(&mut stream,&answer.to_vec().unwrap()).await.unwrap();
    });
    let q=query("large.example");
    let result=tokio::time::timeout(Duration::from_secs(10),exchange(&addr.to_string(),&q)).await.unwrap().unwrap();
    assert_eq!(result.metadata.id,q.metadata.id);assert_eq!(result.answers.len(),1);assert!(!result.metadata.truncation);
    upstream.await.unwrap();
}

#[tokio::test] async fn servfail_is_not_cached_or_replaced_by_unvalidated_forwarding() {
    let sock=UdpSocket::bind("127.0.0.1:0").await.unwrap();let addr=sock.local_addr().unwrap().to_string();
    let upstream=tokio::spawn(async move {for _ in 0..2 {
        let mut buf=vec![0;4096];let (n,src)=sock.recv_from(&mut buf).await.unwrap();let q=Message::from_vec(&buf[..n]).unwrap();
        sock.send_to(&dns::reply(&q,ResponseCode::ServFail).to_vec().unwrap(),src).await.unwrap();
    }});
    let p=proxy(&addr);let q=query("temporary.example").to_vec().unwrap();
    for _ in 0..2 {
        let r=Message::from_vec(&p.process(&q,"192.168.1.3",false).await.unwrap()).unwrap();assert_eq!(r.metadata.response_code,ResponseCode::ServFail);
    }
    tokio::time::timeout(Duration::from_secs(10),upstream).await.unwrap().unwrap();
}

#[tokio::test] async fn tcp_connection_accepts_multiple_queries() {
    let p=proxy("127.0.0.1:1");p.policy.write().await.deny("blocked.example".into());
    let listener=TcpListener::bind("127.0.0.1:0").await.unwrap();let addr=listener.local_addr().unwrap();
    let task=tokio::spawn(async move {p.run_tcp(listener).await});
    let mut stream=TcpStream::connect(addr).await.unwrap();
    for _ in 0..2 {
        let q=query("blocked.example");write_frame(&mut stream,&q.to_vec().unwrap()).await.unwrap();
        let r=Message::from_vec(&tokio::time::timeout(Duration::from_secs(10),read_frame(&mut stream)).await.unwrap().unwrap()).unwrap();
        assert_eq!(r.metadata.response_code,ResponseCode::NXDomain);assert_eq!(r.metadata.id,q.metadata.id);
    }
    task.abort();
}
