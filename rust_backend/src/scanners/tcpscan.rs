use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use std::time::Duration;

const MAX_CONCURRENT_TASKS: usize = 100; // Limit the number of concurrent tasks
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(3); // Timeout for TCP connections

/// Struct to store the results of the TCP port scan
pub struct TcpScanResult {
    open_ports: Vec<(Ipv4Addr, u16)>, // (IP, Port)
    errors: Vec<(Ipv4Addr, String)>,  // (IP, Error Message)
}

impl TcpScanResult {
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
        println!("TCP scan completed.");
        println!("Total open ports: {}", self.open_ports.len());
        println!("Total errors: {}", self.errors.len());
    }
}

/// Function to perform a TCP port scan on a single IP
async fn scan_ports(ip: Ipv4Addr, port_range: std::ops::Range<u16>, semaphore: Arc<Semaphore>) -> TcpScanResult {
    let mut result = TcpScanResult::new();

    let mut tasks = Vec::new();
    for port in port_range {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let ip_clone = ip;
        let task = tokio::spawn(async move {
            let _permit = permit; // Hold the permit for the duration of the task
            let addr = SocketAddr::new(IpAddr::V4(ip_clone), port);
            match tokio::time::timeout(CONNECTION_TIMEOUT, TcpStream::connect(addr)).await {
                Ok(Ok(_)) => Ok((ip_clone, port)), // Port is open
                Ok(Err(e)) => Err(format!("Error connecting to {}:{} - {}", ip_clone, port, e)),
                Err(_) => Err(format!("Timeout connecting to {}:{}", ip_clone, port)),
            }
        });
        tasks.push(task);
    }

    for task in tasks {
        match task.await {
            Ok(Ok((ip, port))) => result.add_open_port(ip, port),
            Ok(Err(e)) => result.add_error(ip, e), // Record the error
            Err(e) => result.add_error(ip, format!("Task failed: {}", e)), // Handle task failure
        }
    }

    result
}
/// Function to perform a TCP port scan on a list of live hosts
pub async fn tcp_scan(live_hosts: &Vec<Ipv4Addr>, port_range: std::ops::Range<u16>) -> TcpScanResult {
    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TASKS));
    let mut final_result = TcpScanResult::new();

    for ip in live_hosts {
        let result = scan_ports(*ip, port_range.clone(), semaphore.clone()).await;
        final_result.open_ports.extend(result.get_open_ports().clone());
        final_result.errors.extend(result.get_errors().clone());
    }

    final_result
}