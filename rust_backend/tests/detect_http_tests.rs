use rust_backend::detect_http;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_detect_http_on_localhost() {
    let ip = Ipv4Addr::LOCALHOST;
    let port = 80;
    let result = detect_http::detect(ip, port).await;
    assert!(result.detected || result.error.is_some());
}