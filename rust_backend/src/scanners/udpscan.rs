use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Semaphore;

const MAX_CONCURRENT_TASKS: usize = 64; // Limit the number of concurrent tasks
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(4); // Timeout for UDP responses

/// Struct to store the results of the UDP port scan
pub struct UdpScanResult {
    open_ports: Vec<(Ipv4Addr, u16)>, // (IP, Port)
    errors: Vec<(Ipv4Addr, String)>,  // (IP, Error Message)
}

impl UdpScanResult {
    pub fn new() -> Self {
        Self {
            open_ports: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn add_open_port(&mut self, ip: Ipv4Addr, port: u16) {
        self.open_ports.push((ip, port));
    }

    pub fn add_error(&mut self, ip: Ipv4Addr, error: String) {
        self.errors.push((ip, error));
    }

    pub fn get_open_ports(&self) -> &Vec<(Ipv4Addr, u16)> {
        &self.open_ports
    }

    pub fn get_errors(&self) -> &Vec<(Ipv4Addr, String)> {
        &self.errors
    }

    pub fn print_summary(&self) {
        println!("UDP scan completed.");
        println!("Total open ports: {}", self.open_ports.len());
        println!("Total errors: {}", self.errors.len());
    }
}

/// Function to perform a UDP port scan on a single IP (Version 2)
async fn scan_udp_ports(
    ip: Ipv4Addr,
    port_range: std::ops::Range<u16>,
    semaphore: Arc<Semaphore>,
) -> UdpScanResult {
    let mut result = UdpScanResult::new();

    let mut tasks = Vec::new();
    for port in port_range {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let ip_clone = ip;
        let task = tokio::spawn(async move {
            let _permit = permit;
            let addr = SocketAddr::new(IpAddr::V4(ip_clone), port);

            match tokio::time::timeout(CONNECTION_TIMEOUT, async {
                let socket = UdpSocket::bind("0.0.0.0:0")
                    .await
                    .map_err(|e| e.to_string())?;
                socket.connect(addr).await.map_err(|e| e.to_string())?;

                if port == 53 {
                    let dns_query = [
                        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                        0x03, b'w', b'w', b'w', 0x07, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
                        0x03, b'c', b'o', b'm', 0x00, 0x00, 0x01, 0x00, 0x01,
                    ];
                    socket.send(&dns_query).await.map_err(|e| e.to_string())?;
                } else {
                    socket.send(&[0u8; 1]).await.map_err(|e| e.to_string())?;
                }

                let mut buf = [0u8; 1024];
                match socket.recv(&mut buf).await {
                    Ok(_) => Ok(()),
                    Err(_) => Err("No response".to_string()),
                }
            })
            .await
            {
                Ok(Ok(_)) => Ok((ip_clone, port)),
                Ok(Err(e)) => Err(format!("Error on {}:{} - {}", ip_clone, port, e)),
                Err(_) => Err(format!("Timeout on {}:{}", ip_clone, port)),
            }
        });
        tasks.push(task);
    }

    for task in tasks {
        match task.await {
            Ok(Ok((ip, port))) => result.add_open_port(ip, port),
            Ok(Err(e)) => result.add_error(ip, e),
            Err(e) => result.add_error(ip, format!("Task failed: {}", e)),
        }
    }

    result
}

pub async fn udp_scan(
    live_hosts: &Vec<Ipv4Addr>,
    port_range: std::ops::Range<u16>,
) -> UdpScanResult {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TASKS));
    let mut final_result = UdpScanResult::new();

    for ip in live_hosts {
        let result = scan_udp_ports(*ip, port_range.clone(), semaphore.clone()).await;
        final_result
            .open_ports
            .extend(result.get_open_ports().clone());
        final_result.errors.extend(result.get_errors().clone());
    }

    final_result
}
