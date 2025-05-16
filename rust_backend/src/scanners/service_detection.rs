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

    let mut last_error = None;

    // --- SSH Detection ---
    match tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = vec![0u8; 256];
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                Ok(Ok(n)) => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    if banner.starts_with("SSH-") {
                        return ServiceDetectionResult::new(port, Some("SSH".to_string()), None);
                    }
                }
                Ok(Err(e)) => {
                    last_error = Some(format!("SSH read error: {}", e));
                }
                Err(_) => {
                    last_error = Some("SSH read timeout".to_string());
                }
            }
        }
        Ok(Err(e)) => {
            last_error = Some(format!("SSH connect error: {}", e));
        }
        Err(_) => {
            last_error = Some("SSH connect timeout".to_string());
        }
    }

    // --- FTP Detection (port 21) ---
    match tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = vec![0u8; 256];
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                Ok(Ok(n)) => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    if banner.contains("FTP") {
                        return ServiceDetectionResult::new(port, Some("FTP".to_string()), None);
                    }
                }
                Ok(Err(e)) => {
                    last_error = Some(format!("FTP read error: {}", e));
                }
                Err(_) => {
                    last_error = Some("FTP read timeout".to_string());
                }
            }
        }
        Ok(Err(e)) => {
            last_error = Some(format!("FTP connect error: {}", e));
        }
        Err(_) => {
            last_error = Some("FTP connect timeout".to_string());
        }
    }

    // --- SMTP Detection (port 25, 587, 465) ---
    match tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = vec![0u8; 256];
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                Ok(Ok(n)) => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    if banner.contains("SMTP") || banner.contains("ESMTP") {
                        return ServiceDetectionResult::new(port, Some("SMTP".to_string()), None);
                    }
                }
                Ok(Err(e)) => {
                    last_error = Some(format!("SMTP read error: {}", e));
                }
                Err(_) => {
                    last_error = Some("SMTP read timeout".to_string());
                }
            }
        }
        Ok(Err(e)) => {
            last_error = Some(format!("SMTP connect error: {}", e));
        }
        Err(_) => {
            last_error = Some("SMTP connect timeout".to_string());
        }
    }

    // --- POP3 Detection (port 110) ---
    match tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let mut buf = vec![0u8; 256];
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                Ok(Ok(n)) => {
                    let banner = String::from_utf8_lossy(&buf[..n]);
                    if banner.contains("+OK") && banner.to_lowercase().contains("pop3") {
                        return ServiceDetectionResult::new(port, Some("POP3".to_string()), None);
                    }
                }
                Ok(Err(e)) => {
                    last_error = Some(format!("POP3 read error: {}", e));
                }
                Err(_) => {
                    last_error = Some("POP3 read timeout".to_string());
                }
            }
        }
        Ok(Err(e)) => {
            last_error = Some(format!("POP3 connect error: {}", e));
        }
        Err(_) => {
            last_error = Some("POP3 connect timeout".to_string());
        }
    }

    // --- HTTP Detection ---
    match tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let host = ip.to_string();
            let http_probe = format!("GET / HTTP/1.0\r\nHost: {}\r\n\r\n", host);
            if let Err(e) = stream.write_all(http_probe.as_bytes()).await {
                last_error = Some(format!("HTTP write error: {}", e));
            } else {
                let mut buf = vec![0u8; 512];
                match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                    Ok(Ok(n)) => {
                        let resp = String::from_utf8_lossy(&buf[..n]);
                        if resp.contains("HTTP/1.1") || resp.contains("HTTP/1.0") {
                            return ServiceDetectionResult::new(
                                port,
                                Some("HTTP".to_string()),
                                None,
                            );
                        }
                    }
                    Ok(Err(e)) => {
                        last_error = Some(format!("HTTP read error: {}", e));
                    }
                    Err(_) => {
                        last_error = Some("HTTP read timeout".to_string());
                    }
                }
            }
        }
        Ok(Err(e)) => {
            last_error = Some(format!("HTTP connect error: {}", e));
        }
        Err(_) => {
            last_error = Some("HTTP connect timeout".to_string());
        }
    }

    // --- HTTPS Detection ---
    match tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            let connector = TlsConnector::from(native_tls::TlsConnector::new().unwrap());
            let host = ip.to_string();
            match tokio::time::timeout(Duration::from_secs(3), connector.connect(&host, stream))
                .await
            {
                Ok(Ok(_tls_stream)) => {
                    return ServiceDetectionResult::new(port, Some("HTTPS".to_string()), None);
                }
                Ok(Err(e)) => {
                    last_error = Some(format!("HTTPS handshake error: {}", e));
                }
                Err(_) => {
                    last_error = Some("HTTPS handshake timeout".to_string());
                }
            }
        }
        Ok(Err(e)) => {
            last_error = Some(format!("HTTPS connect error: {}", e));
        }
        Err(_) => {
            last_error = Some("HTTPS connect timeout".to_string());
        }
    }

    // --- Fallback ---
    ServiceDetectionResult::new(port, Some("Unknown Service".to_string()), last_error)
}

pub async fn service_scan(ip: Ipv4Addr, open_ports: Vec<u16>) -> Vec<ServiceDetectionResult> {
    use futures::future::join_all;

    let futures = open_ports.into_iter().map(|port| {
        println!("Scanning port {port}...");
        detect_service(ip, port)
    });
    join_all(futures).await
}
