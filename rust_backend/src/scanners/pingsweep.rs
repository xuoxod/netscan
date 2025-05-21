use pnet::packet::Packet;
use pnet::packet::icmp::{IcmpPacket, IcmpTypes, echo_reply};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::transport::{
    TransportChannelType::Layer4, TransportProtocol, icmp_packet_iter, transport_channel,
};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

pub struct LiveHost {
    pub ip: Ipv4Addr,
    pub ttl: Option<u8>,
}

pub async fn ping_sweep(subnet: &str) -> Vec<LiveHost> {
    // ...parse subnet into IPs...
    let mut live_hosts = Vec::new();

    // For each IP, send ICMP EchoRequest and wait for EchoReply
    for ip in ips_in_subnet(subnet) {
        // ...send ICMP EchoRequest...
        if let Some((reply, ttl)) = send_icmp_and_get_reply(ip) {
            live_hosts.push(LiveHost { ip, ttl: Some(ttl) });
        }
    }
    live_hosts
}

// Helper: Guess OS from TTL
pub fn guess_os_from_ttl(ttl: u8) -> &'static str {
    match ttl {
        60..=70 => "Linux/Unix",
        120..=130 => "Windows",
        240..=255 => "Network Device/Router",
        _ => "Unknown",
    }
}

// ...rest of your code...
