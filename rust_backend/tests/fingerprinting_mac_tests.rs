use rust_backend::fingerprint_mac;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_fingerprint_mac_on_localhost() {
    let ip = Ipv4Addr::LOCALHOST;
    let result = fingerprint_mac::fingerprint(ip).await;
    // Accept None for now, but must not panic
    assert!(result.mac.is_none() || result.error.is_some());
}