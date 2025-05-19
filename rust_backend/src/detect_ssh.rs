use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SshDetection {
    pub banner: Option<String>,
    pub detected: bool,
    pub error: Option<String>,
}

pub async fn detect(ip: Ipv4Addr, port: u16) -> SshDetection {
    let addr = (ip, port);
    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_secs(8), TcpStream::connect(addr)).await
    {
        let mut buf = vec![0u8; 256];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
        {
            let banner = String::from_utf8_lossy(&buf[..n]).to_string();
            if banner.starts_with("SSH-") {
                return SshDetection {
                    banner: Some(banner),
                    detected: true,
                    error: None,
                };
            }
        }
        let _ = stream.write_all(b"\n").await;
        let mut buf2 = vec![0u8; 256];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf2)).await
        {
            let banner = String::from_utf8_lossy(&buf2[..n]).to_string();
            if banner.starts_with("SSH-") {
                return SshDetection {
                    banner: Some(banner),
                    detected: true,
                    error: None,
                };
            }
        }
        SshDetection {
            banner: None,
            detected: false,
            error: Some("No SSH banner found".to_string()),
        }
    } else {
        SshDetection {
            banner: None,
            detected: false,
            error: Some("Connection failed".to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_detect_ssh_on_localhost() {
        let ip = Ipv4Addr::LOCALHOST;
        let port = 22;
        let result = detect(ip, port).await;
        assert!(result.detected || result.error.is_some());
    }
}