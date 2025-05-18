use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

//
// ====================
// Trait-Based Detection System (not used by CLI, but kept for extensibility)
// ====================
//

pub trait ProtocolDetector {
    fn name(&self) -> &'static str;
    fn can_attempt(&self, port: u16) -> bool;
    fn detect(&self, ip: std::net::IpAddr, port: u16) -> DetectionResult;
}

pub struct DetectionResult {
    pub port: u16,
    pub protocol: String,
    pub success: bool,
    pub details: Option<String>,
}

pub struct HttpDetector;
impl ProtocolDetector for HttpDetector {
    fn name(&self) -> &'static str {
        "HTTP"
    }
    fn can_attempt(&self, port: u16) -> bool {
        port == 80 || port == 8080 || port == 8000
    }
    fn detect(&self, ip: std::net::IpAddr, port: u16) -> DetectionResult {
        // ...actual HTTP detection logic...
        DetectionResult {
            port,
            protocol: "HTTP".to_string(),
            success: false,
            details: Some("Not implemented".to_string()),
        }
    }
}

pub fn detect_services(ip: std::net::IpAddr, ports: &[u16]) -> Vec<DetectionResult> {
    let detectors: Vec<Box<dyn ProtocolDetector>> = vec![
        Box::new(HttpDetector),
        // Box::new(FtpDetector), // Add more as you implement them
    ];

    let mut results = Vec::new();
    for &port in ports {
        for detector in &detectors {
            if detector.can_attempt(port) {
                let result = detector.detect(ip, port);
                results.push(result);
            }
        }
    }
    results
}

//
// ====================
// Async/CLI-Driven Detection System (used by main.rs and CLI)
// ====================
//

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Ssh,
    Ftp,
    Smtp,
    Http,
    Https,
    Dns,
    Pop3,
    Imap,
    Telnet,
}

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct ServiceDetectionResult {
    pub port: u16,
    pub service: Option<String>,
    pub error: Option<String>,
    pub protocol_failures: Vec<String>,
}

impl ServiceDetectionResult {
    pub fn new(
        port: u16,
        service: Option<String>,
        error: Option<String>,
        protocol_failures: Vec<String>,
    ) -> Self {
        Self {
            port,
            service,
            error,
            protocol_failures,
        }
    }
}

/// Returns the default port list: all ports 0-1024 inclusive.
pub fn default_ports() -> Vec<u16> {
    (0..=1024).collect()
}

/// Merge user-supplied ports into the default list, deduplicated and sorted.
fn merged_ports(user_ports: Option<Vec<u16>>) -> Vec<u16> {
    let mut set: HashSet<u16> = default_ports().into_iter().collect();
    if let Some(custom) = user_ports {
        for p in custom {
            set.insert(p);
        }
    }
    let mut ports: Vec<u16> = set.into_iter().collect();
    ports.sort_unstable();
    ports
}

pub async fn detect_service(
    ip: Ipv4Addr,
    port: u16,
    protocols: &[Protocol],
) -> ServiceDetectionResult {
    use tokio_native_tls::TlsConnector;
    let addr = SocketAddr::new(IpAddr::V4(ip), port);

    let mut errors = Vec::new();
    let mut protocol_failures = Vec::new();

    for proto in protocols {
        match proto {
            Protocol::Ssh => {
                if port == 22 {
                    if let Ok(Ok(mut stream)) =
                        tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                    {
                        let mut buf = vec![0u8; 256];
                        if let Ok(Ok(n)) =
                            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
                                .await
                        {
                            let banner = String::from_utf8_lossy(&buf[..n]);
                            if banner.starts_with("SSH-") {
                                return ServiceDetectionResult::new(
                                    port,
                                    Some("SSH".to_string()),
                                    None,
                                    protocol_failures,
                                );
                            }
                        }
                    } else {
                        errors.push("SSH: connect/read failed".to_string());
                        protocol_failures.push("SSH".to_string());
                    }
                }
            }
            Protocol::Ftp => {
                if port == 21 {
                    if let Ok(Ok(mut stream)) =
                        tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                    {
                        let mut buf = vec![0u8; 256];
                        if let Ok(Ok(n)) =
                            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
                                .await
                        {
                            let banner = String::from_utf8_lossy(&buf[..n]);
                            if banner.contains("FTP") {
                                return ServiceDetectionResult::new(
                                    port,
                                    Some("FTP".to_string()),
                                    None,
                                    protocol_failures,
                                );
                            }
                        }
                    } else {
                        errors.push("FTP: connect/read failed".to_string());
                        protocol_failures.push("FTP".to_string());
                    }
                }
            }
            Protocol::Smtp => {
                if [25, 465, 587].contains(&port) {
                    if let Ok(Ok(mut stream)) =
                        tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                    {
                        let mut buf = vec![0u8; 256];
                        if let Ok(Ok(n)) =
                            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
                                .await
                        {
                            let banner = String::from_utf8_lossy(&buf[..n]);
                            if banner.contains("SMTP") || banner.contains("ESMTP") {
                                return ServiceDetectionResult::new(
                                    port,
                                    Some("SMTP".to_string()),
                                    None,
                                    protocol_failures,
                                );
                            }
                        }
                    } else {
                        errors.push("SMTP: connect/read failed".to_string());
                        protocol_failures.push("SMTP".to_string());
                    }
                }
            }
            Protocol::Http => {
                if port == 80 || port == 8080 {
                    if let Ok(Ok(mut stream)) =
                        tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                    {
                        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
                        let mut buf = vec![0u8; 256];
                        if let Ok(Ok(n)) =
                            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
                                .await
                        {
                            let banner = String::from_utf8_lossy(&buf[..n]);
                            if banner.contains("HTTP/1.0") || banner.contains("HTTP/1.1") {
                                return ServiceDetectionResult::new(
                                    port,
                                    Some("HTTP".to_string()),
                                    None,
                                    protocol_failures,
                                );
                            }
                        }
                    } else {
                        errors.push("HTTP: connect/read failed".to_string());
                        protocol_failures.push("HTTP".to_string());
                    }
                }
            }
            Protocol::Https => {
                if port == 443 {
                    // You can implement a TLS handshake or just try to connect for now
                    // For simplicity, just try to connect
                    if let Ok(Ok(_stream)) =
                        tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                    {
                        // Optionally, try a TLS handshake here
                        return ServiceDetectionResult::new(
                            port,
                            Some("HTTPS (maybe)".to_string()),
                            None,
                            protocol_failures,
                        );
                    } else {
                        errors.push("HTTPS: connect failed".to_string());
                        protocol_failures.push("HTTPS".to_string());
                    }
                }
            }

            Protocol::Dns => {
                if port == 53 {
                    // Simple UDP DNS query (no response parsing, just check if port is open)
                    use tokio::net::UdpSocket;
                    let socket = UdpSocket::bind("0.0.0.0:0").await;
                    if let Ok(sock) = socket {
                        let dns_query = [
                            0x12, 0x34, // ID
                            0x01, 0x00, // Standard query
                            0x00, 0x01, // QDCOUNT
                            0x00, 0x00, // ANCOUNT
                            0x00, 0x00, // NSCOUNT
                            0x00, 0x00, // ARCOUNT
                            0x03, b'w', b'w', b'w', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03, b'c', b'o', b'm', 0x00, // www.google.com
                            0x00, 0x01, // Type A
                            0x00, 0x01, // Class IN
                        ];
                        let _ = sock.send_to(&dns_query, (ip, port)).await;
                        // If send succeeds, assume DNS is open
                        return ServiceDetectionResult::new(
                            port,
                            Some("DNS".to_string()),
                            None,
                            protocol_failures,
                        );
                    } else {
                        errors.push("DNS: UDP send failed".to_string());
                        protocol_failures.push("DNS".to_string());
                    }
                }
            }
            Protocol::Pop3 => {
                if port == 110 {
                    if let Ok(Ok(mut stream)) =
                        tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                    {
                        let mut buf = vec![0u8; 128];
                        if let Ok(Ok(n)) =
                            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                        {
                            let banner = String::from_utf8_lossy(&buf[..n]);
                            if banner.contains("+OK") {
                                return ServiceDetectionResult::new(
                                    port,
                                    Some("POP3".to_string()),
                                    None,
                                    protocol_failures,
                                );
                            }
                        }
                    } else {
                        errors.push("POP3: connect/read failed".to_string());
                        protocol_failures.push("POP3".to_string());
                    }
                }
            }
            Protocol::Imap => {
                if port == 143 {
                    if let Ok(Ok(mut stream)) =
                        tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                    {
                        let mut buf = vec![0u8; 128];
                        if let Ok(Ok(n)) =
                            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                        {
                            let banner = String::from_utf8_lossy(&buf[..n]);
                            if banner.contains("* OK") {
                                return ServiceDetectionResult::new(
                                    port,
                                    Some("IMAP".to_string()),
                                    None,
                                    protocol_failures,
                                );
                            }
                        }
                    } else {
                        errors.push("IMAP: connect/read failed".to_string());
                        protocol_failures.push("IMAP".to_string());
                    }
                }
            }
            Protocol::Telnet => {
                if port == 23 {
                    if let Ok(Ok(mut stream)) =
                        tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                    {
                        let mut buf = vec![0u8; 128];
                        if let Ok(Ok(n)) =
                            tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                        {
                            let banner = String::from_utf8_lossy(&buf[..n]);
                            if banner.contains("login") || banner.contains("Welcome") {
                                return ServiceDetectionResult::new(
                                    port,
                                    Some("Telnet".to_string()),
                                    None,
                                    protocol_failures,
                                );
                            }
                        }
                    } else {
                        errors.push("Telnet: connect/read failed".to_string());
                        protocol_failures.push("Telnet".to_string());
                    }
                }
            }
        }
    }

    // --- Generic Banner Detection (for unknown services) ---
    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
    {
        let mut buf = vec![0u8; 256];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
        {
            let banner = String::from_utf8_lossy(&buf[..n]);
            if !banner.trim().is_empty() {
                return ServiceDetectionResult::new(
                    port,
                    Some(format!("Banner: {}", banner.trim())),
                    None,
                    protocol_failures,
                );
            }
        }
    }

    // --- Fallback ---
    let error = if errors.is_empty() {
        None
    } else {
        Some(errors.join(" | "))
    };
    ServiceDetectionResult::new(
        port,
        Some("Unknown Service".to_string()),
        error,
        protocol_failures,
    )
}

/// Scan the given ports, or use the default if `user_ports` is None.
/// User ports are merged and deduplicated with the default list.
pub async fn service_scan(
    ip: Ipv4Addr,
    user_ports: Option<Vec<u16>>,
    protocols: &[Protocol],
) -> Vec<ServiceDetectionResult> {
    use futures::future::join_all;

    let ports = merged_ports(user_ports);

    let futures = ports.into_iter().map(|port| {
        println!("Scanning port {port}...");
        detect_service(ip, port, protocols)
    });
    join_all(futures).await
}
