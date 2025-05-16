use rust_backend::scanners::udpscan::udp_scan;
use std::net::Ipv4Addr;

#[tokio::test]
async fn test_udp_scan_valid_host() {
    let live_hosts = vec![Ipv4Addr::new(192, 168, 1, 1)]; // Replace with a valid host on your network
    let port_range = 53..54; // Example: DNS port
    let result = udp_scan(&live_hosts, port_range).await;

    println!("Open ports: {:?}", result.get_open_ports());
    println!("Errors: {:?}", result.get_errors());

    assert!(result.get_open_ports().len() > 0, "No open ports found!"); // Expect at least one open port
    assert!(
        result.get_errors().is_empty(),
        "Errors occurred during the scan!"
    ); // No errors expected
}

#[tokio::test]
async fn test_udp_scan_invalid_host() {
    let live_hosts = vec![Ipv4Addr::new(192, 0, 2, 1)]; // Reserved IP (unreachable)
    let port_range = 1..10;
    let result = udp_scan(&live_hosts, port_range).await;

    assert!(
        result.get_open_ports().is_empty(),
        "Unexpected open ports found!"
    ); // No open ports expected
    assert!(
        !result.get_errors().is_empty(),
        "No errors recorded for invalid host!"
    ); // Errors expected
}

#[tokio::test]
async fn test_udp_scan_empty_port_range() {
    let live_hosts = vec![Ipv4Addr::new(127, 0, 0, 1)]; // Localhost
    let port_range = 0..0; // Empty range
    let result = udp_scan(&live_hosts, port_range).await;

    assert!(
        result.get_open_ports().is_empty(),
        "Unexpected open ports found!"
    ); // No open ports expected
    assert!(
        result.get_errors().is_empty(),
        "Unexpected errors recorded!"
    ); // No errors expected
}

#[tokio::test]
async fn test_udp_scan_multiple_hosts() {
    let live_hosts = vec![
        Ipv4Addr::new(127, 0, 0, 1),   // Localhost
        Ipv4Addr::new(192, 168, 1, 1), // Replace with a valid host
        Ipv4Addr::new(192, 0, 2, 1),   // Reserved IP (unreachable)
    ];
    let port_range = 53..55; // Example: DNS and another port
    let result = udp_scan(&live_hosts, port_range).await;

    println!("Open ports: {:?}", result.get_open_ports());
    println!("Errors: {:?}", result.get_errors());

    // Check for at least one open port on valid hosts
    assert!(
        result.get_open_ports().len() > 0,
        "No open ports found on valid hosts!"
    );

    // Ensure errors are recorded for unreachable hosts
    assert!(
        result.get_errors().len() > 0,
        "No errors recorded for unreachable hosts!"
    );
}
