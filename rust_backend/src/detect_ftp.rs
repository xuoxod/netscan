use std::net::Ipv4Addr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::io::AsyncReadExt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpDetection {
    pub detected: bool,
    pub banner: Option<String>,
    pub error: Option<String>,
}

pub async fn detect(ip: Ipv4Addr, port: u16) -> FtpDetection {
    let addr = (ip, port);
    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_secs(5), TcpStream::connect(addr)).await
    {
        let mut buf = vec![0u8; 256];
        if let Ok(Ok(n)) =
            tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await
        {
            let banner = String::from_utf8_lossy(&buf[..n]).to_string();
            if banner.contains("FTP") {
                return FtpDetection {
                    detected: true,
                    banner: Some(banner),
                    error: None,
                };
            }
        }
        FtpDetection {
            detected: false,
            banner: None,
            error: Some("No FTP banner".to_string()),
        }
    } else {
        FtpDetection {
            detected: false,
            banner: None,
            error: Some("Connection failed".to_string()),
        }
    }
}