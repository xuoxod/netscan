use rust_backend::detect_dns;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_detect_dns_on_localhost() {
    let ip = Ipv4Addr::LOCALHOST;
    let port = 53;
    let result = detect_dns::detect(ip, port).await;
    assert!(result.detected || result.error.is_some());
}

#[tokio::test]
async fn test_detect_dns_on_invalid_port() {
    let ip = Ipv4Addr::LOCALHOST;
    let port = 65000;
    let result = detect_dns::detect(ip, port).await;
    assert!(!result.detected);
    assert!(result.error.is_some());
}