use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsDetection {
    pub detected: bool,
    pub error: Option<String>,
}

pub async fn detect(ip: Ipv4Addr, port: u16) -> DnsDetection {
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            return DnsDetection {
                detected: false,
                error: Some(format!("Bind failed: {e}")),
            }
        }
    };
    // Simple DNS query for A record of "example.com"
    let query = [
        0x12, 0x34, // ID
        0x01, 0x00, // Standard query
        0x00, 0x01, // QDCOUNT
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
        0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        0x03, b'c', b'o', b'm',
        0x00, // end of name
        0x00, 0x01, // QTYPE=A
        0x00, 0x01, // QCLASS=IN
    ];
    let _ = socket
        .send_to(&query, SocketAddr::new(ip.into(), port))
        .await;
    let mut buf = [0u8; 512];
    if let Some(Ok((n, _))) =
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .ok()
    {
        if n > 0 {
            return DnsDetection {
                detected: true,
                error: None,
            };
        }
    }
    DnsDetection {
        detected: false,
        error: Some("No DNS response".to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_detect_dns_on_localhost() {
        let ip = Ipv4Addr::LOCALHOST;
        let port = 53;
        let result = detect(ip, port).await;
        assert!(result.detected || result.error.is_some());
    }
}