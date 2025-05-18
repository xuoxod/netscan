use pnet::packet::icmp::{IcmpTypes};
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::Packet;
use pnet::transport::{icmp_packet_iter, transport_channel, TransportChannelType, TransportProtocol};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

const ICMP_PACKET_SIZE: usize = 64;
const MAX_CONCURRENT_TASKS: usize = 64; // Limit the number of concurrent tasks
const TIMEOUT_SECONDS: u64 = 5; // Timeout for ICMP response

/// Struct to store the results of the ping sweep
#[derive(Debug)] // Ensure the syntax is correct and Debug is properly imported
pub struct PingSweepResult {
    live_hosts: Vec<Ipv4Addr>,
    not_alive_hosts: Vec<Ipv4Addr>,
    errors: Vec<(Ipv4Addr, String)>, // Store errors with IPs
}

impl PingSweepResult {
    pub fn new() -> Self {
        Self {
            live_hosts: Vec::new(),
            not_alive_hosts: Vec::new(),
            errors: Vec::new(),
        }
    }

    pub fn add_live_host(&mut self, ip: Ipv4Addr) {
        self.live_hosts.push(ip);
    }

    pub fn add_not_alive_host(&mut self, ip: Ipv4Addr) {
        self.not_alive_hosts.push(ip);
    }

    pub fn add_error(&mut self, ip: Ipv4Addr, error: String) {
        self.errors.push((ip, error));
    }

    pub fn get_live_hosts(&self) -> &Vec<Ipv4Addr> {
        &self.live_hosts
    }

    pub fn get_not_alive_hosts(&self) -> &Vec<Ipv4Addr> {
        &self.not_alive_hosts
    }

    pub fn get_errors(&self) -> &Vec<(Ipv4Addr, String)> {
        &self.errors
    }

    pub fn print_summary(&self) {
        println!("Ping sweep completed.");
        println!("Total live hosts: {}", self.live_hosts.len());
        println!("Total not-alive hosts: {}", self.not_alive_hosts.len());
        println!("Total errors: {}", self.errors.len());
    }
}

/// Function to check if a host is alive using ICMP Echo Request
fn is_host_alive(ip: Ipv4Addr) -> Result<bool, String> {
    let mut buffer = [0u8; ICMP_PACKET_SIZE];
    let mut packet = MutableEchoRequestPacket::new(&mut buffer).unwrap();

    packet.set_icmp_type(IcmpTypes::EchoRequest);
    packet.set_sequence_number(1);
    packet.set_identifier(1);

    let immutable_packet = packet.to_immutable();
    let icmp_packet = IcmpPacket::new(immutable_packet.packet()).ok_or("Failed to create ICMP packet")?;
    let checksum = pnet::packet::icmp::checksum(&icmp_packet);
    packet.set_checksum(checksum);

    let (mut tx, mut rx) = transport_channel(
        1024,
        TransportChannelType::Layer4(TransportProtocol::Ipv4(pnet::packet::ip::IpNextHeaderProtocols::Icmp)),
    )
    .map_err(|e| format!("Failed to create transport channel: {}", e))?;

    let target = IpAddr::V4(ip);
    tx.send_to(packet, target)
        .map_err(|e| format!("Failed to send ICMP request to {}: {}", ip, e))?;

    let mut iter = icmp_packet_iter(&mut rx);

    let timeout_duration = Duration::from_secs(TIMEOUT_SECONDS);
    match iter.next_with_timeout(timeout_duration) {
        Ok(Some((packet, addr))) => {
            if addr == target {
                if let Some(icmp_packet) = IcmpPacket::new(packet.packet()) {
                    if icmp_packet.get_icmp_type() == IcmpTypes::EchoReply {
                        return Ok(true);
                    }
                }
            }
        }
        Ok(None) => {
            return Ok(false); // No response within timeout
        }
        Err(e) => {
            return Err(format!("Error receiving response: {}", e));
        }
    }

    Ok(false)
}

/// Function to perform a ping sweep on a given subnet
pub async fn ping_sweep(subnet: &str) -> Result<PingSweepResult, String> {
    let ips = parse_subnet(subnet)?;
    let mut result = PingSweepResult::new();

    let semaphore = Arc::new(Semaphore::new(MAX_CONCURRENT_TASKS));
    let mut tasks = Vec::new();

    for ip in ips {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let task = tokio::spawn(async move {
            let _permit = permit;
            (ip, is_host_alive(ip))
        });
        tasks.push(task);
    }

    for task in tasks {
        match task.await {
            Ok((ip, Ok(true))) => result.add_live_host(ip),
            Ok((ip, Ok(false))) => result.add_not_alive_host(ip),
            Ok((ip, Err(e))) => result.add_error(ip, e),
            Err(e) => result.add_error(Ipv4Addr::new(0, 0, 0, 0), format!("Task failed: {}", e)),
        }
    }

    Ok(result)
}

/// Function to parse a subnet in CIDR notation and return a list of IP addresses
pub fn parse_subnet(subnet: &str) -> Result<Vec<Ipv4Addr>, String> {
    let parts: Vec<&str> = subnet.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid subnet format. Use CIDR notation (e.g., 192.168.1.0/24).".to_string());
    }

    let base_ip: Ipv4Addr = parts[0].parse().map_err(|_| "Invalid IP address.".to_string())?;
    let prefix: u32 = parts[1].parse().map_err(|_| "Invalid prefix.".to_string())?;

    if prefix > 32 {
        return Err("Invalid prefix.".to_string());
    }

    let mut ips = Vec::new();
    let num_ips = 2u32.pow(32 - prefix);
    for i in 0..num_ips {
        let ip = Ipv4Addr::from(u32::from(base_ip) + i);
        ips.push(ip);
    }

    Ok(ips)
}