use rust_backend::scanners::tcpscan::tcp_scan;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_tcp_scan_valid_host() {
    let live_hosts = vec![Ipv4Addr::new(192,168,1,158)]; // Localhost for testing
    let port_range = 30778..30779; // Common ports (e.g., SSH, Telnet)
    let result = tcp_scan(&live_hosts, port_range).await;

    assert!(result.get_open_ports().len() > 0); // Expect at least one open port
    assert!(result.get_errors().is_empty()); // No errors expected
}

#[tokio::test]
async fn test_tcp_scan_invalid_host() {
    let live_hosts = vec![Ipv4Addr::new(192, 0, 2, 1)]; // Reserved IP (unreachable)
    let port_range = 1..10;
    let result = tcp_scan(&live_hosts, port_range).await;

    assert!(result.get_open_ports().is_empty()); // No open ports expected
    assert!(!result.get_errors().is_empty()); // Errors expected
}

#[tokio::test]
async fn test_tcp_scan_empty_port_range() {
    let live_hosts = vec![Ipv4Addr::new(127, 0, 0, 1)];
    let port_range = 0..0; // Empty range
    let result = tcp_scan(&live_hosts, port_range).await;

    assert!(result.get_open_ports().is_empty()); // No open ports expected
    assert!(result.get_errors().is_empty()); // No errors expected
}