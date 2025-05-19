use rust_backend::detect_ftp;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_detect_ftp_on_localhost() {
    let ip = Ipv4Addr::LOCALHOST;
    let port = 21;
    let result = detect_ftp::detect(ip, port).await;
    assert!(result.detected || result.error.is_some());
}

#[tokio::test]
async fn test_detect_ftp_on_invalid_port() {
    let ip = Ipv4Addr::LOCALHOST;
    let port = 65000;
    let result = detect_ftp::detect(ip, port).await;
    assert!(!result.detected);
    assert!(result.error.is_some());
}