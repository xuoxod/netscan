use std::net::Ipv4Addr;
use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::time::Duration;
use std::thread;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacFingerprint {
    pub mac: Option<MacAddr>,
    pub vendor: Option<String>,
    pub error: Option<String>,
}

pub async fn fingerprint(ip: Ipv4Addr) -> MacFingerprint {
    // Only works on local subnet!
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.is_up() && !iface.is_loopback() && !iface.ips.is_empty())
        .expect("No suitable network interface found");

    let source_mac = interface.mac.unwrap();
    let source_ip = interface
        .ips
        .iter()
        .find_map(|ip| if let std::net::IpAddr::V4(ipv4) = ip.ip() { Some(ipv4) } else { None })
        .unwrap();

    let (mut tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => {
            return MacFingerprint {
                mac: None,
                vendor: None,
                error: Some("Unhandled channel type".to_string()),
            }
        }
        Err(e) => {
            return MacFingerprint {
                mac: None,
                vendor: None,
                error: Some(format!("Failed to create datalink channel: {e}")),
            }
        }
    };

    // Build ARP request
    let mut ethernet_buffer = [0u8; 42];
    {
        let mut eth_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();
        eth_packet.set_destination(MacAddr::broadcast());
        eth_packet.set_source(source_mac);
        eth_packet.set_ethertype(EtherTypes::Arp);

        let mut arp_buffer = [0u8; 28];
        let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();
        arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
        arp_packet.set_protocol_type(EtherTypes::Ipv4);
        arp_packet.set_hw_addr_len(6);
        arp_packet.set_proto_addr_len(4);
        arp_packet.set_operation(ArpOperations::Request);
        arp_packet.set_sender_hw_addr(source_mac);
        arp_packet.set_sender_proto_addr(source_ip);
        arp_packet.set_target_hw_addr(MacAddr::zero());
        arp_packet.set_target_proto_addr(ip);

        eth_packet.set_payload(arp_packet.packet());
    }

    // Send ARP request
    match tx.send_to(&ethernet_buffer, None) {
        Some(Ok(_)) => {},
        Some(Err(e)) => {
            return MacFingerprint {
                mac: None,
                vendor: None,
                error: Some(format!("Failed to send ARP request: {e:?}")),
            };
        }
        None => {
            return MacFingerprint {
                mac: None,
                vendor: None,
                error: Some("Failed to send ARP request: no tx available".to_string()),
            };
        }
    }

    // Wait for ARP reply (timeout: 1s)
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(1) {
        match rx.next() {
            Ok(packet) => {
                if let Some(eth_packet) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                    if eth_packet.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp_packet) = ArpPacket::new(eth_packet.payload()) {
                            if arp_packet.get_operation() == ArpOperations::Reply
                                && arp_packet.get_sender_proto_addr() == ip
                            {
                                let mac = arp_packet.get_sender_hw_addr();
                                return MacFingerprint {
                                    mac: Some(mac),
                                    vendor: None, // Optionally, look up vendor by MAC prefix
                                    error: None,
                                };
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    MacFingerprint {
        mac: None,
        vendor: None,
        error: Some("No ARP reply received".to_string()),
    }
}