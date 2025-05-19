use rust_backend::detect_ssh;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_detect_ssh_on_localhost() {
    let ip = Ipv4Addr::LOCALHOST;
    let port = 22;
    let result = detect_ssh::detect(ip, port).await;
    assert!(result.detected || result.error.is_some());
}

#[tokio::test]
pub async fn test_detect_ssh_on_invalid_port() {
    let ip = Ipv4Addr::LOCALHOST;
    let port = 65000;
    let result = detect_ssh::detect(ip, port).await;
    assert!(!result.detected);
    assert!(result.error.is_some());
}