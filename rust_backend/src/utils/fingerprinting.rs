use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The result of host fingerprinting.
#[derive(Debug, Clone)]
pub struct HostFingerprintResult {
    pub ip: Ipv4Addr,
    pub os: Option<String>,
    pub vendor: Option<String>,
    pub serial: Option<String>,
    pub details: Option<String>,
}

impl HostFingerprintResult {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            os: None,
            vendor: None,
            serial: None,
            details: None,
        }
    }
}

// SSH Banner
async fn fingerprint_ssh(ip: Ipv4Addr) -> Option<String> {
    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect((ip, 22))).await
    {
        let mut buf = vec![0u8; 256];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
        {
            let banner = String::from_utf8_lossy(&buf[..n]);
            if banner.starts_with("SSH-") {
                return Some(banner.trim().to_string());
            }
        }
    }
    None
}

// HTTP Banner
async fn fingerprint_http(ip: Ipv4Addr, port: u16) -> Option<String> {
    let addr = SocketAddr::new(ip.into(), port);
    if let Ok(Ok(mut stream)) =
        tokio::time::timeout(Duration::from_secs(3), TcpStream::connect(addr)).await
    {
        let _ = stream
            .write_all(b"HEAD / HTTP/1.0\r\nHost: example\r\n\r\n")
            .await;
        let mut buf = vec![0u8; 512];
        if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await
        {
            let banner = String::from_utf8_lossy(&buf[..n]);
            if banner.contains("Server:") || banner.contains("HTTP/") {
                return Some(banner.trim().to_string());
            }
        }
    }
    None
}

// SNMP sysDescr (using snmp crate, blocking in spawn_blocking)
async fn fingerprint_snmp(ip: Ipv4Addr) -> Option<String> {
    tokio::task::spawn_blocking(move || {
        use snmp::{SyncSession, Value};
        let target = format!("{}:161", ip);
        if let Ok(mut sess) =
            SyncSession::new(target.as_str(), b"public", Some(Duration::from_secs(2)), 0)
        {
            if let Ok(mut pdu) = sess.get(&[1, 3, 6, 1, 2, 1, 1, 1, 0]) {
                if let Some((_, Value::OctetString(desc))) = pdu.varbinds.next() {
                    return Some(String::from_utf8_lossy(&desc).to_string());
                }
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

// NetBIOS Name Query (UDP 137, basic implementation)
async fn fingerprint_netbios(ip: Ipv4Addr) -> Option<String> {
    use tokio::net::UdpSocket;
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return None,
    };
    let query = [
        0xAB, 0xCD, // Transaction ID
        0x01, 0x10, // Flags
        0x00, 0x01, // Questions
        0x00, 0x00, // Answer RRs
        0x00, 0x00, // Authority RRs
        0x00, 0x00, // Additional RRs
        // Name (workgroup/host, wildcard)
        0x20, b'C', b'K', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
        b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A', b'A',
        b'A', b'A', b'A', 0x00, 0x00, 0x21, // NBSTAT
        0x00, 0x01, // IN
    ];
    let _ = socket
        .send_to(&query, SocketAddr::new(ip.into(), 137))
        .await;
    let mut buf = [0u8; 512];
    if let Some(Ok((n, _))) =
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .ok()
    {
        // Parse NetBIOS name response (very basic)
        if n > 57 {
            let name = String::from_utf8_lossy(&buf[57..(57 + 15).min(n)])
                .trim()
                .to_string();
            return Some(name);
        }
    }
    None
}

// TCP/IP Stack (simple TTL probe)
async fn fingerprint_tcpip_stack(ip: Ipv4Addr) -> Option<String> {
    use tokio::net::UdpSocket;
    let socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(_) => return None,
    };
    let _ = socket
        .send_to(&[0], SocketAddr::new(ip.into(), 33434))
        .await; // Traceroute-style
    let mut buf = [0u8; 512];
    if let Some(Ok((n, _))) =
        tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
            .await
            .ok()
    {
        // In real stack fingerprinting, you'd analyze the TTL, window size, etc.
        return Some(format!("UDP response size: {}", n));
    }
    None
}

// MAC Vendor (local ARP table, using mac_address crate)
async fn fingerprint_mac_vendor(_ip: Ipv4Addr) -> Option<String> {
    use mac_address::get_mac_address;
    if let Ok(Some(mac)) = get_mac_address() {
        let oui = mac.to_string()[..8].replace(":", "-").to_uppercase();
        return Some(format!("MAC: {}", oui));
    }
    None
}

/// Attempt to fingerprint a host using available techniques.
/// This is async and can be called for each live host.
pub async fn fingerprint_host(ip: Ipv4Addr) -> HostFingerprintResult {
    let mut result = HostFingerprintResult::new(ip);

    // SSH
    if let Some(banner) = fingerprint_ssh(ip).await {
        result.details = Some(format!("SSH: {}", banner));
        if let Some(idx) = banner.find("OpenSSH_") {
            let os_info = banner[idx..]
                .split_whitespace()
                .nth(1)
                .unwrap_or("")
                .to_string();
            result.os = Some(os_info);
        }
    }

    // HTTP
    if let Some(banner) = fingerprint_http(ip, 80).await {
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!("\nHTTP: {}", banner));
    }

    // SNMP
    if let Some(sysdescr) = fingerprint_snmp(ip).await {
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!("\nSNMP: {}", sysdescr));
    }

    // NetBIOS/SMB
    if let Some(nb) = fingerprint_netbios(ip).await {
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!("\nNetBIOS: {}", nb));
    }

    // MAC Vendor
    if let Some(mac) = fingerprint_mac_vendor(ip).await {
        result.vendor = Some(mac);
    }

    // TCP/IP Stack
    if let Some(stack) = fingerprint_tcpip_stack(ip).await {
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!("\nTCP/IP: {}", stack));
    }

    result
}
