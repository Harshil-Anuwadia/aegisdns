#[tokio::main]
async fn main() {
    let res = tokio::net::lookup_host(("big.oisd.nl", 443)).await;
    println!("{:?}", res);
}
