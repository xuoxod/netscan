use rust_backend::scanners::pingsweep::{ping_sweep, parse_subnet};

#[test]
fn test_valid_subnet_parsing() {
    let result = parse_subnet("192.168.1.0/24");
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 256); // 2^(32-24) = 256
}

#[test]
fn test_invalid_subnet_format() {
    let result = parse_subnet("192.168.1.0");
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "Invalid subnet format. Use CIDR notation (e.g., 192.168.1.0/24)."
    );
}

#[test]
fn test_invalid_ip_address() {
    let result = parse_subnet("999.999.999.999/24");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Invalid IP address.");
}

#[test]
fn test_invalid_prefix() {
    let result = parse_subnet("192.168.1.0/33");
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Invalid prefix.");
}

#[tokio::test]
async fn test_ping_sweep_valid_subnet() {
    let result = ping_sweep("192.168.1.0/30").await; // Small subnet for testing
    assert!(result.is_ok());
    let live_hosts = result.unwrap();
    assert!(live_hosts.get_live_hosts().len() <= 4); // Max 4 IPs in /30 subnet
}

#[tokio::test]
async fn test_ping_sweep_invalid_subnet() {
    let result = ping_sweep("192.168.1.0").await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "Invalid subnet format. Use CIDR notation (e.g., 192.168.1.0/24)."
    );
}

#[tokio::test]
async fn test_ping_sweep_empty_subnet() {
    let result = ping_sweep("").await;
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "Invalid subnet format. Use CIDR notation (e.g., 192.168.1.0/24)."
    );
}