use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct ServiceDetectionResult {
    pub port: u16,
    pub service: Option<String>,
    pub error: Option<String>,
}

impl ServiceDetectionResult {
    pub fn new(port: u16, service: Option<String>, error: Option<String>) -> Self {
        Self {
            port,
            service,
            error,
        }
    }
}

pub async fn detect_service(ip: Ipv4Addr, port: u16) -> ServiceDetectionResult {
    use tokio_native_tls::TlsConnector;
    let addr = SocketAddr::new(IpAddr::V4(ip), port);

    let mut errors = Vec::new();

    // --- SSH Detection ---
    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
    {
        let mut buf = vec![0u8; 256];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
        {
            let banner = String::from_utf8_lossy(&buf[..n]);
            if banner.starts_with("SSH-") {
                return ServiceDetectionResult::new(port, Some("SSH".to_string()), None);
            }
        }
    } else {
        errors.push("SSH: connect/read failed".to_string());
    }

    // --- FTP Detection ---
    if port == 21 {
        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
        {
            let mut buf = vec![0u8; 256];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
            {
                let banner = String::from_utf8_lossy(&buf[..n]);
                if banner.contains("FTP") {
                    return ServiceDetectionResult::new(port, Some("FTP".to_string()), None);
                }
            }
        } else {
            errors.push("FTP: connect/read failed".to_string());
        }
    }

    // --- SMTP Detection ---
    if [25, 465, 587].contains(&port) {
        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
        {
            let mut buf = vec![0u8; 256];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
            {
                let banner = String::from_utf8_lossy(&buf[..n]);
                if banner.contains("SMTP") || banner.contains("ESMTP") {
                    return ServiceDetectionResult::new(port, Some("SMTP".to_string()), None);
                }
            }
        } else {
            errors.push("SMTP: connect/read failed".to_string());
        }
    }

    // --- POP3 Detection ---
    if port == 110 {
        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
        {
            let mut buf = vec![0u8; 256];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
            {
                let banner = String::from_utf8_lossy(&buf[..n]);
                if banner.contains("+OK") && banner.to_lowercase().contains("pop3") {
                    return ServiceDetectionResult::new(port, Some("POP3".to_string()), None);
                }
            }
        } else {
            errors.push("POP3: connect/read failed".to_string());
        }
    }

    // --- DNS Detection (TCP) ---
    if port == 53 {
        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
        {
            // Build a minimal DNS query for root A record, with TCP length prefix
            let dns_query = [
                0x12, 0x34, // ID
                0x01, 0x00, // Standard query
                0x00, 0x01, // QDCOUNT (1 question)
                0x00, 0x00, // ANCOUNT
                0x00, 0x00, // NSCOUNT
                0x00, 0x00, // ARCOUNT
                0x00, // root label
                0x00, 0x01, // Type A
                0x00, 0x01, // Class IN
            ];
            let query_len = dns_query.len() as u16;
            let mut tcp_query = Vec::with_capacity(2 + dns_query.len());
            tcp_query.extend_from_slice(&(query_len.to_be_bytes())); // TCP length prefix
            tcp_query.extend_from_slice(&dns_query);

            if stream.write_all(&tcp_query).await.is_ok() {
                let mut buf = vec![0u8; 512];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                {
                    // DNS over TCP: first two bytes are length
                    if n >= 4 {
                        let resp_len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
                        if resp_len + 2 <= n && buf[2] == 0x12 && buf[3] == 0x34 {
                            // Transaction ID matches, likely a DNS response
                            return ServiceDetectionResult::new(
                                port,
                                Some("DNS".to_string()),
                                None,
                            );
                        }
                    }
                }
            }
        } else {
            errors.push("DNS: connect/read failed".to_string());
        }
    }

    // --- Telnet Detection ---
    if port == 23 {
        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
        {
            let mut buf = vec![0u8; 256];
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
            {
                let banner = String::from_utf8_lossy(&buf[..n]);
                if banner.contains("Telnet") || banner.contains("login:") {
                    return ServiceDetectionResult::new(port, Some("Telnet".to_string()), None);
                }
            }
        } else {
            errors.push("Telnet: connect/read failed".to_string());
        }
    }

    // --- HTTP Detection ---
    if [80, 8080, 8000, 8888].contains(&port) {
        if let Ok(Ok(mut stream)) =
            tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
        {
            let host = ip.to_string();
            let http_probe = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
            if stream.write_all(http_probe.as_bytes()).await.is_ok() {
                let mut buf = vec![0u8; 512];
                if let Ok(Ok(n)) =
                    tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
                {
                    let resp = String::from_utf8_lossy(&buf[..n]);
                    if resp.contains("HTTP/1.1") || resp.contains("HTTP/1.0") {
                        return ServiceDetectionResult::new(port, Some("HTTP".to_string()), None);
                    }
                }
            }
        } else {
            errors.push("HTTP: connect/read failed".to_string());
        }
    }

    // --- HTTPS Detection ---
    if [443, 8443, 9443].contains(&port) {
        if let Ok(Ok(stream)) =
            tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await
        {
            let connector = native_tls::TlsConnector::builder()
                .danger_accept_invalid_certs(true) // Accept self-signed certs
                .build()
                .unwrap();
            let connector = TlsConnector::from(connector);
            let host = ip.to_string();
            match tokio::time::timeout(Duration::from_secs(3), connector.connect(&host, stream))
                .await
            {
                Ok(Ok(_tls_stream)) => {
                    return ServiceDetectionResult::new(port, Some("HTTPS".to_string()), None);
                }
                Ok(Err(e)) => {
                    errors.push(format!("HTTPS handshake error: {}", e));
                }
                Err(_) => {
                    errors.push("HTTPS handshake timeout".to_string());
                }
            }
        } else {
            errors.push("HTTPS: connect failed".to_string());
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
    ServiceDetectionResult::new(port, Some("Unknown Service".to_string()), error)
}

pub async fn service_scan(ip: Ipv4Addr, open_ports: Vec<u16>) -> Vec<ServiceDetectionResult> {
    use futures::future::join_all;

    let futures = open_ports.into_iter().map(|port| {
        println!("Scanning port {port}...");
        detect_service(ip, port)
    });
    join_all(futures).await
}
