//! Shared DNS wire handling. Never construct replies by copying untrusted header counts.
use hickory_proto::{op::{Edns, Message, MessageType, OpCode, ResponseCode}, rr::{DNSClass, RData, Record, rdata::{A, CNAME, SOA}, Name}};

pub fn parse_query(bytes: &[u8]) -> Option<Message> {
    let q = Message::from_vec(bytes).ok()?;
    if q.metadata.message_type != MessageType::Query || q.metadata.op_code != OpCode::Query
        || q.queries.len() != 1 || !q.answers.is_empty() || !q.authorities.is_empty()
        || q.queries[0].query_class != DNSClass::IN || q.signature.is_some() { return None; }
    Some(q)
}

pub fn reply(q: &Message, code: ResponseCode) -> Message {
    let mut m = Message::response(q.metadata.id, q.metadata.op_code);
    m.metadata.recursion_desired = q.metadata.recursion_desired;
    m.metadata.recursion_available = true;
    m.metadata.checking_disabled = q.metadata.checking_disabled;
    m.metadata.response_code = code;
    m.queries = q.queries.clone();
    if q.edns.is_some() {
        let mut e = Edns::new(); e.set_max_payload(1232); m.edns = Some(e);
    }
    m
}

pub fn negative(q: &Message, code: ResponseCode) -> Message {
    let mut m = reply(q, code);
    let name = q.queries[0].name.clone();
    m.add_authority(Record::from_rdata(name, 30, RData::SOA(SOA::new(Name::root(), Name::root(), 1, 60, 60, 60, 30))));
    m
}

pub fn ipv4_reply(q: &Message, ip: std::net::Ipv4Addr) -> Message {
    let mut m = reply(q, ResponseCode::NoError);
    m.add_answer(Record::from_rdata(q.queries[0].name.clone(), 30, RData::A(A(ip))));
    m
}

pub fn cname_reply(q: &Message, target: &str) -> Option<Message> {
    let target = Name::from_ascii(target).ok()?;
    let mut m = reply(q, ResponseCode::NoError);
    m.add_answer(Record::from_rdata(q.queries[0].name.clone(), 60, RData::CNAME(CNAME(target))));
    Some(m)
}

pub fn valid_response(q: &Message, r: &Message) -> bool {
    if r.metadata.message_type != MessageType::Response { return false; }
    if r.metadata.id != q.metadata.id { return false; }
    if r.metadata.op_code != q.metadata.op_code { return false; }
    if r.queries.len() != q.queries.len() { return false; }
    r.queries.iter().zip(q.queries.iter()).all(|(rq, qq)| {
        rq.query_type() == qq.query_type()
            && rq.query_class() == qq.query_class()
            && rq.name().to_utf8().to_lowercase().trim_end_matches('.') == qq.name().to_utf8().to_lowercase().trim_end_matches('.')
    })
}

pub fn encode_for_client(m: &Message, q: &Message, tcp: bool) -> Option<Vec<u8>> {
    let bytes = m.to_vec().ok()?;
    let size = q.edns.as_ref().map(|e| e.max_payload().clamp(512, 1232)).unwrap_or(512) as usize;
    if !tcp && bytes.len() > size { m.truncate().to_vec().ok() } else { Some(bytes) }
}

pub fn local_zone(domain: &str) -> bool {
    ["root", "aegis", "lan", "home.arpa"].iter().any(|suffix| domain == *suffix || domain.ends_with(&format!(".{suffix}")))
}

#[cfg(test)] mod tests {
    use super::*;
    use hickory_proto::{op::Query, rr::RecordType};
    #[test] fn synthetic_answers_clear_ad_and_roundtrip() {
        let mut q = Message::query(); q.add_query(Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A));
        q.metadata.authentic_data = true; q.set_edns(Edns::new());
        let r = negative(&q, ResponseCode::NXDomain);
        assert!(!r.metadata.authentic_data);
        let parsed = Message::from_vec(&r.to_vec().unwrap()).unwrap();
        assert!(valid_response(&q, &parsed)); assert_eq!(parsed.authorities.len(), 1);
        let mut mismatch = parsed.clone(); mismatch.queries[0].name = Name::from_ascii("different.com").unwrap(); assert!(!valid_response(&q, &mismatch));
        mismatch = parsed; mismatch.metadata.message_type = MessageType::Query; assert!(!valid_response(&q, &mismatch));
    }
    #[test] fn large_answers_truncate_for_udp_only() {
        let mut q = Message::query(); q.add_query(Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A));
        let mut r = reply(&q, ResponseCode::NoError);
        for n in 0..100 { r.add_answer(Record::from_rdata(q.queries[0].name.clone(), 60, RData::A(A(std::net::Ipv4Addr::new(8,8,8,n))))); }
        assert!(Message::from_vec(&encode_for_client(&r,&q,false).unwrap()).unwrap().metadata.truncation);
        assert!(!Message::from_vec(&encode_for_client(&r,&q,true).unwrap()).unwrap().metadata.truncation);
    }
    #[test] fn cname_answers_support_all_redirected_query_types() {
        let mut q = Message::query(); q.add_query(Query::query(Name::from_ascii("www.google.com").unwrap(), RecordType::AAAA));
        let r=cname_reply(&q,"forcesafesearch.google.com.").unwrap();
        assert_eq!(r.answers.len(),1);
        assert!(matches!(&r.answers[0].data,RData::CNAME(name) if name.0.to_ascii()=="forcesafesearch.google.com."));
    }
}
