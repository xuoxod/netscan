use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
                let ssh = crate::detect_ssh::detect(ip, port).await;
                if ssh.detected {
                    return ServiceDetectionResult::new(
                        port,
                        Some("SSH".to_string()),
                        None,
                        protocol_failures,
                    );
                }
                errors.push(
                    ssh.error
                        .unwrap_or_else(|| "SSH detection failed".to_string()),
                );
                protocol_failures.push("SSH".to_string());
            }
            Protocol::Http => {
                let http = crate::detect_http::detect(ip, port).await;
                if http.detected {
                    return ServiceDetectionResult::new(
                        port,
                        Some("HTTP".to_string()),
                        None,
                        protocol_failures,
                    );
                }
                errors.push(
                    http.error
                        .unwrap_or_else(|| "HTTP detection failed".to_string()),
                );
                protocol_failures.push("HTTP".to_string());
            }
            Protocol::Dns => {
                let dns = crate::detect_dns::detect(ip, port).await;
                if dns.detected {
                    return ServiceDetectionResult::new(
                        port,
                        Some("DNS".to_string()),
                        None,
                        protocol_failures,
                    );
                }
                errors.push(
                    dns.error
                        .unwrap_or_else(|| "DNS detection failed".to_string()),
                );
                protocol_failures.push("DNS".to_string());
            }

            Protocol::Smtp => {
                let smtp = crate::detect_smtp::detect(ip, port).await;
                if smtp.detected {
                    return ServiceDetectionResult::new(
                        port,
                        Some("SMTP".to_string()),
                        None,
                        protocol_failures,
                    );
                }
                errors.push(
                    smtp.error
                        .unwrap_or_else(|| "SMTP detection failed".to_string()),
                );
                protocol_failures.push("SMTP".to_string());
            }
            Protocol::Ftp => {
                let ftp = crate::detect_ftp::detect(ip, port).await;
                if ftp.detected {
                    return ServiceDetectionResult::new(
                        port,
                        Some("FTP".to_string()),
                        None,
                        protocol_failures,
                    );
                }
                errors.push(
                    ftp.error
                        .unwrap_or_else(|| "FTP detection failed".to_string()),
                );
                protocol_failures.push("FTP".to_string());
            }

            _ => {
                protocol_failures.push(format!("{:?}", proto));
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
            if banner.starts_with("SSH-") {
                return ServiceDetectionResult::new(
                    port,
                    Some("SSH".to_string()),
                    None,
                    protocol_failures,
                );
            }
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

/// Scan only the user-supplied ports (no defaults, no merging).
pub async fn service_scan(
    ip: Ipv4Addr,
    user_ports: Option<Vec<u16>>,
    protocols: &[Protocol],
) -> Vec<ServiceDetectionResult> {
    use futures::stream::{self, StreamExt};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    let ports = user_ports.unwrap_or_default();
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
