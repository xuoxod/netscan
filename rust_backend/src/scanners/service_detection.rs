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
const SSH_CONNECTION_TIMEOUT: Duration = Duration::from_secs(9);

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

    println!(
        "DEBUG: detect_service called for port {} with protocols {:?}",
        port, protocols
    );

    for proto in protocols {
        match proto {
            Protocol::Ssh => {
                // print!("\n\t\tScanning SSH on port {}...\n", port);

                if let Ok(Ok(mut stream)) =
                    tokio::time::timeout(SSH_CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                {
                    let mut buf = vec![0u8; 256];
                    // Try to read the banner first
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(8), stream.read(&mut buf)).await
                    {
                        let banner = String::from_utf8_lossy(&buf[..n]);
                        println!("DEBUG: SSH banner on port {}: {:?}", port, banner);
                        if banner.starts_with("SSH-") {
                            return ServiceDetectionResult::new(
                                port,
                                Some("SSH".to_string()),
                                None,
                                protocol_failures,
                            );
                        }
                    }
                    // If no banner, try sending a newline to prompt a response
                    let _ = stream.write_all(b"\n").await;
                    let mut buf2 = vec![0u8; 256];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(8), stream.read(&mut buf2)).await
                    {
                        let banner = String::from_utf8_lossy(&buf2[..n]);
                        println!(
                            "DEBUG: SSH banner (after newline) on port {}: {:?}",
                            port, banner
                        );
                        if banner.starts_with("SSH-") {
                            print!("\nSSH Connection Established on port {}...\n", port);

                            return ServiceDetectionResult::new(
                                port,
                                Some("SSH".to_string()),
                                None,
                                protocol_failures,
                            );
                        }
                    }
                } else {
                    // print!("\n\t\tSSH Connection Failed on port {}...\n", port);
                    errors.push("SSH: connection timeout".to_string());
                }
                // errors.push("SSH: no valid SSH banner".to_string());
                // protocol_failures.push("SSH".to_string());
                // println!("DEBUG: Returning SSH detection result for port {}", port);
            }
            Protocol::Ftp => {
                if let Ok(Ok(mut stream)) =
                    tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                {
                    let mut buf = vec![0u8; 256];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                    {
                        let banner = String::from_utf8_lossy(&buf[..n]);
                        // FTP banners typically contain "FTP"
                        if banner.contains("FTP") {
                            print!("\nSSH FTP Established on port {}...\n", port);

                            return ServiceDetectionResult::new(
                                port,
                                Some("FTP".to_string()),
                                None,
                                protocol_failures,
                            );
                        }
                    }
                }
                errors.push("FTP: no valid FTP banner".to_string());
                protocol_failures.push("FTP".to_string());
            }
            Protocol::Smtp => {
                if let Ok(Ok(mut stream)) =
                    tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                {
                    let mut buf = vec![0u8; 256];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                    {
                        let banner = String::from_utf8_lossy(&buf[..n]);
                        // SMTP banners typically contain "SMTP" or "ESMTP"
                        if banner.contains("SMTP") || banner.contains("ESMTP") {
                            print!("\nSSH SMTP Established on port {}...\n", port);

                            return ServiceDetectionResult::new(
                                port,
                                Some("SMTP".to_string()),
                                None,
                                protocol_failures,
                            );
                        }
                    }
                }
                errors.push("SMTP: no valid SMTP banner".to_string());
                protocol_failures.push("SMTP".to_string());
            }
            Protocol::Http => {
                if let Ok(Ok(mut stream)) =
                    tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                {
                    let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
                    let mut buf = vec![0u8; 256];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                    {
                        let banner = String::from_utf8_lossy(&buf[..n]);
                        // HTTP responses contain "HTTP/1.0" or "HTTP/1.1"
                        if banner.contains("HTTP/1.0") || banner.contains("HTTP/1.1") {
                            print!("\nSSH HTTP Established on port {}...\n", port);

                            return ServiceDetectionResult::new(
                                port,
                                Some("HTTP".to_string()),
                                None,
                                protocol_failures,
                            );
                        }
                    }
                }
                errors.push("HTTP: no valid HTTP response".to_string());
                protocol_failures.push("HTTP".to_string());
            }
            Protocol::Https => {
                if let Ok(Ok(stream)) =
                    tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                {
                    // Try a TLS handshake
                    if let Ok(connector) = native_tls::TlsConnector::new() {
                        let connector = TlsConnector::from(connector);
                        if let Ok(Ok(mut tls_stream)) = tokio::time::timeout(
                            Duration::from_secs(2),
                            connector.connect("localhost", stream),
                        )
                        .await
                        {
                            // Try to read a response
                            let mut buf = vec![0u8; 256];
                            if let Ok(Ok(n)) = tokio::time::timeout(
                                Duration::from_secs(2),
                                tls_stream.read(&mut buf),
                            )
                            .await
                            {
                                let banner = String::from_utf8_lossy(&buf[..n]);
                                // HTTPS responses may contain "HTTP/1.1" or a TLS handshake
                                if banner.contains("HTTP/1.1") || !banner.trim().is_empty() {
                                    print!("\nSSH HTTPS Established on port {}...\n", port);

                                    return ServiceDetectionResult::new(
                                        port,
                                        Some("HTTPS".to_string()),
                                        None,
                                        protocol_failures,
                                    );
                                }
                            }
                        }
                    }
                }
                errors.push("HTTPS: no valid TLS handshake".to_string());
                protocol_failures.push("HTTPS".to_string());
            }
            Protocol::Dns => {
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
                        0x03, b'w', b'w', b'w', 0x06, b'g', b'o', b'o', b'g', b'l', b'e', 0x03,
                        b'c', b'o', b'm', 0x00, // www.google.com
                        0x00, 0x01, // Type A
                        0x00, 0x01, // Class IN
                    ];
                    let _ = sock.send_to(&dns_query, (ip, port)).await;
                    let mut buf = [0u8; 512];
                    if let Ok(Ok((n, _))) =
                        tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await
                    {
                        // Check if the response ID matches our query
                        if n >= 2 && buf[0] == 0x12 && buf[1] == 0x34 {
                            print!("\nSSH DNS Established on port {}...\n", port);

                            return ServiceDetectionResult::new(
                                port,
                                Some("DNS".to_string()),
                                None,
                                protocol_failures,
                            );
                        }
                    }
                }
                errors.push("DNS: no valid DNS response".to_string());
                protocol_failures.push("DNS".to_string());
            }
            Protocol::Pop3 => {
                if let Ok(Ok(mut stream)) =
                    tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                {
                    let mut buf = vec![0u8; 128];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                    {
                        let banner = String::from_utf8_lossy(&buf[..n]);
                        // POP3 banners typically start with "+OK"
                        if banner.starts_with("+OK") {
                            print!("\nSSH POP3 Established on port {}...\n", port);

                            return ServiceDetectionResult::new(
                                port,
                                Some("POP3".to_string()),
                                None,
                                protocol_failures,
                            );
                        }
                    }
                }
                errors.push("POP3: no valid POP3 banner".to_string());
                protocol_failures.push("POP3".to_string());
            }
            Protocol::Imap => {
                if let Ok(Ok(mut stream)) =
                    tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                {
                    let mut buf = vec![0u8; 128];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                    {
                        let banner = String::from_utf8_lossy(&buf[..n]);
                        // IMAP banners typically start with "* OK"
                        if banner.starts_with("* OK") {
                            print!("\nSSH IMAP Established on port {}...\n", port);

                            return ServiceDetectionResult::new(
                                port,
                                Some("IMAP".to_string()),
                                None,
                                protocol_failures,
                            );
                        }
                    }
                }
                errors.push("IMAP: no valid IMAP banner".to_string());
                protocol_failures.push("IMAP".to_string());
            }
            Protocol::Telnet => {
                if let Ok(Ok(mut stream)) =
                    tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
                {
                    let mut buf = vec![0u8; 128];
                    if let Ok(Ok(n)) =
                        tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                    {
                        let banner = String::from_utf8_lossy(&buf[..n]);
                        // Telnet banners often contain "login" or "Welcome"
                        if banner.contains("login") || banner.contains("Welcome") {
                            print!("\nSSH Telnet Established on port {}...\n", port);

                            return ServiceDetectionResult::new(
                                port,
                                Some("Telnet".to_string()),
                                None,
                                protocol_failures,
                            );
                        }
                    }
                }
                errors.push("Telnet: no valid Telnet banner".to_string());
                protocol_failures.push("Telnet".to_string());
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
                print!("\nSSH Generic Banner Established on port {}...\n", port);

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
    use futures::stream::{self, StreamExt};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let ports = merged_ports(user_ports);
    let semaphore = Arc::new(Semaphore::new(64)); // Limit to 64 concurrent scans

    let results = stream::iter(ports.into_iter())
        .map(|port| {
            let ip = ip.clone();
            let protocols = protocols.to_vec();
            let semaphore = semaphore.clone();
            async move {
                let _permit = semaphore.acquire().await.unwrap();
                detect_service(ip, port, &protocols).await
            }
        })
        .buffer_unordered(64)
        .collect()
        .await;

    results
}
