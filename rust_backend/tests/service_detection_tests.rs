use rust_backend::scanners::service_detection::{detect_service, service_scan};
use rust_backend::utils::prettyprint::pretty_print_service_results;

use rust_backend::scanners::service_detection::Protocol;

const PROTOCOLS: &[Protocol] = &[
    Protocol::Ssh,
    Protocol::Ftp,
    Protocol::Smtp,
    Protocol::Http,
    Protocol::Dns,
];

fn get_test_ip() -> std::net::Ipv4Addr {
    std::env::var("TEST_IP")
        .ok()
        .and_then(|ip| ip.parse().ok())
        .unwrap_or(std::net::Ipv4Addr::new(127, 0, 0, 1))
}

#[tokio::test]
async fn test_service_scan() {
    let open_ports = vec![80, 443, 22, 30778, 53, 21, 153, 20, 19, 23, 148, 9999];
    let ip = get_test_ip();
    let results = service_scan(ip, Some(open_ports.clone()), PROTOCOLS).await;

    pretty_print_service_results("Service Scan Results", &results);

    assert_eq!(results.len(), open_ports.len());
}

#[tokio::test]
async fn test_service_scan_default() {
    let ip = get_test_ip();
    let results = service_scan(ip, None, PROTOCOLS).await;
    // Just check that we scanned the right number of ports
    assert_eq!(results.len(), 1025); // ports 0..=1024
}

#[tokio::test]
async fn test_detect_service_http() {
    let port = 80;
    let ip = get_test_ip();
    let result = detect_service(ip, port, PROTOCOLS).await;

    println!("HTTP detection result:\n{:#?}", result);
    if let Some(err) = &result.error {
        println!("Error for port {}: {}", port, err);
    }
    assert!(
        result.service == Some("HTTP".to_string())
            || result.service == Some("Unknown Service".to_string()),
        "Expected HTTP or Unknown Service, got: {:?}",
        result.service
    );
}

#[tokio::test]
async fn test_detect_service_https() {
    let port = 443;
    let ip = get_test_ip();
    let result = detect_service(ip, port, PROTOCOLS).await;

    println!("HTTPS detection result: {:?}", result);
    if let Some(err) = &result.error {
        println!("Error for port {}: {}", port, err);
    }
    assert!(
        result.service == Some("HTTPS".to_string())
            || result.service == Some("Unknown Service".to_string()),
        "Expected HTTPS or Unknown Service, got: {:?}",
        result.service
    );
}

#[tokio::test]
async fn test_detect_service_ssh() {
    let port = 22;
    let ip = get_test_ip();
    let result = detect_service(ip, port, PROTOCOLS).await;

    println!("SSH detection result: {:?}", result);
    if let Some(err) = &result.error {
        println!("Error for port {}: {}", port, err);
    }
    assert!(
        result.service == Some("SSH".to_string())
            || result.service == Some("Unknown Service".to_string()),
        "Expected SSH or Unknown Service, got: {:?}",
        result.service
    );
}

#[tokio::test]
async fn test_detect_service_non_traditional_ssh() {
    let port = 30778;
    let ip = get_test_ip();
    let result = detect_service(ip, port, PROTOCOLS).await;

    println!("Non-traditional SSH detection result: {:?}", result);
    if let Some(err) = &result.error {
        println!("Error for port {}: {}", port, err);
    }
    assert!(
        result.service == Some("SSH".to_string())
            || result.service == Some("Unknown Service".to_string()),
        "Expected SSH or Unknown Service, got: {:?}",
        result.service
    );
}

#[tokio::test]
async fn test_detect_service_unknown() {
    let port = 9999;
    let ip = get_test_ip();
    let result = detect_service(ip, port, PROTOCOLS).await;

    println!("Unknown service detection result: {:?}", result);
    if let Some(err) = &result.error {
        println!("Error for port {}: {}", port, err);
    }
    assert_eq!(result.service, Some("Unknown Service".to_string()));
}

#[tokio::test]
async fn test_service_scan_() {
    let open_ports = vec![80, 443, 22, 30778, 53, 21, 153, 20, 19, 23, 148, 9999];
    let ip = get_test_ip();
    let results = service_scan(ip, Some(open_ports.clone()), PROTOCOLS).await;

    println!("Service scan results:");
    for res in &results {
        println!(
            "  Port {:5}: {:20} Error: {:?}",
            res.port,
            res.service.as_deref().unwrap_or("-"),
            res.error.as_deref().unwrap_or("-")
        );
    }

    assert_eq!(results.len(), open_ports.len());
}

#[tokio::test]
async fn test_detect_service_ftp() {
    let port = 21;
    let ip = get_test_ip();
    let result = detect_service(ip, port, PROTOCOLS).await;

    println!("FTP detection result:\n{:#?}", result);
    if let Some(err) = &result.error {
        println!("Error for port {}: {}", port, err);
    }
    assert!(
        result.service == Some("FTP".to_string())
            || result.service == Some("Unknown Service".to_string()),
        "Expected FTP or Unknown Service, got: {:?}",
        result.service
    );
}

#[tokio::test]
async fn test_detect_service_smtp() {
    // Common SMTP ports: 25, 587, 465
    for port in [25, 587, 465] {
        let ip = get_test_ip();
        let result = detect_service(ip, port, PROTOCOLS).await;

        println!("SMTP detection result (port {}):\n{:#?}", port, result);
        if let Some(err) = &result.error {
            println!("Error for port {}: {}", port, err);
        }
        assert!(
            result.service == Some("SMTP".to_string())
                || result.service == Some("Unknown Service".to_string()),
            "Expected SMTP or Unknown Service, got: {:?}",
            result.service
        );
    }
}

#[tokio::test]
async fn test_detect_service_pop3() {
    let port = 110;
    let ip = get_test_ip();
    let result = detect_service(ip, port, PROTOCOLS).await;

    println!("POP3 detection result:\n{:#?}", result);
    if let Some(err) = &result.error {
        println!("Error for port {}: {}", port, err);
    }
    assert!(
        result.service == Some("POP3".to_string())
            || result.service == Some("Unknown Service".to_string()),
        "Expected POP3 or Unknown Service, got: {:?}",
        result.service
    );
}
