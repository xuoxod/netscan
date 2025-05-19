use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpDetection {
    pub detected: bool,
    pub banner: Option<String>,
    pub error: Option<String>,
}

pub async fn detect(ip: Ipv4Addr, port: u16) -> HttpDetection {
    let addr = (ip, port);
    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await
    {
        let _ = stream.write_all(b"HEAD / HTTP/1.0\r\n\r\n").await;
        let mut buf = vec![0u8; 512];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await
        {
            let banner = String::from_utf8_lossy(&buf[..n]).to_string();
            if banner.contains("HTTP/1.0") || banner.contains("HTTP/1.1") {
                return HttpDetection {
                    detected: true,
                    banner: Some(banner),
                    error: None,
                };
            }
        }
        HttpDetection {
            detected: false,
            banner: None,
            error: Some("No HTTP banner".to_string()),
        }
    } else {
        HttpDetection {
            detected: false,
            banner: None,
            error: Some("Connection failed".to_string()),
        }
    }
}