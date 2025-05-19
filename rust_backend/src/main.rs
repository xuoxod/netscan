use clap::{Parser, ValueEnum};
use colored::*;
use rust_backend::scanners::service_detection::{self, Protocol};
use rust_backend::scanners::{pingsweep, tcpscan, udpscan};
use rust_backend::utils::{fingerprinting, prettyprint};
use std::net::{IpAddr, Ipv4Addr};
use local_ip_address::local_ip;

#[derive(ValueEnum, Clone, Debug)]
pub enum ProtocolArg {
    Ssh,
    Ftp,
    Smtp,
    Http,
    Https,
    Dns,
    Pop3,
    Imap,
    Telnet,
}

impl ProtocolArg {
    pub fn to_protocol(&self) -> Protocol {
        match self {
            ProtocolArg::Ssh => Protocol::Ssh,
            ProtocolArg::Ftp => Protocol::Ftp,
            ProtocolArg::Smtp => Protocol::Smtp,
            ProtocolArg::Http => Protocol::Http,
            ProtocolArg::Https => Protocol::Https,
            ProtocolArg::Dns => Protocol::Dns,
            ProtocolArg::Pop3 => Protocol::Pop3,
            ProtocolArg::Imap => Protocol::Imap,
            ProtocolArg::Telnet => Protocol::Telnet,
        }
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "NetScan",
    version,
    author,
    about = "A fast, flexible, and extensible network scanner with host discovery, fingerprinting, and service detection.",
    long_about = "NetScan always performs live host discovery (ping sweep) before any scan or detection. \
You can scan a single IP or an entire subnet. \
All scans and detections operate only on discovered live hosts. \
You must specify which ports and protocols to scan or detect—there are no defaults. \
Features include TCP/UDP port scanning, service detection, and host fingerprinting (OS/vendor/etc).",
    after_help = "\
EXAMPLES:
    netscan --ip 192.168.1.1 --ports 22,80 --protocols ssh,http --service-detection
    netscan --ip 192.168.1.0/24 --tcpscan --ports 22,80,443
    netscan --ip 10.0.0.5 --ports 21,22,25 --protocols ftp,ssh,smtp --service-detection
    netscan --ip 127.0.0.1 --ports 8080 --protocols http --service-detection
    netscan --ip 192.168.1.0/24 --fingerprint

OPTIONS:
    --fingerprint         Attempt OS/vendor fingerprinting on live hosts
    --tcpscan             Perform TCP port scan on live hosts
    --udpscan             Perform UDP port scan on live hosts
    --service-detection   Detect services on live hosts/ports (requires --ports and --protocols)
    -p, --ports           Ports to scan (comma-separated or ranges, e.g. 22,80,443,1000-1010) [REQUIRED for scan/service-detection]
    -r, --protocols       Protocols to detect (comma-separated, e.g. ssh,ftp,smtp) [REQUIRED for service-detection]
    -i, --ip              Target IPv4 address or subnet (CIDR)
    -v, --verbose         Enable verbose output

NOTES:
    - Live host discovery is always performed first.
    - All scans and detections operate only on discovered live hosts.
    - You must specify --ports for any scan or detection.
    - You must specify --protocols for service detection.
    - Run as root for best results (especially for ping sweep).
"
)]
pub struct Cli {
    #[arg(
        short,
        long,
        value_name = "IP",
        help = "Target IPv4 address or subnet (e.g., 192.168.1.1 or 192.168.1.0/24)"
    )]
    ip: String,
    #[arg(
        short = 'p',
        long,
        value_name = "PORTS",
        help = "Ports to scan (comma-separated or ranges, e.g. 22,80,443,1000-1010). REQUIRED for scan/service-detection."
    )]
    ports: Option<String>,
    #[arg(
        short = 'r',
        long,
        value_name = "PROTOCOLS",
        value_enum,
        use_value_delimiter = true,
        help = "Protocols to detect (comma-separated, e.g. ssh,ftp,smtp). REQUIRED for service-detection."
    )]
    protocols: Option<Vec<ProtocolArg>>,
    #[arg(short, long, help = "Enable verbose output")]
    verbose: bool,
    #[arg(long, help = "Fingerprint live hosts after discovery")]
    fingerprint: bool,
    #[arg(long, help = "Perform TCP scan on live hosts")]
    tcpscan: bool,
    #[arg(long, help = "Perform UDP scan on live hosts")]
    udpscan: bool,
    #[arg(long, help = "Perform service detection on live hosts")]
    service_detection: bool,
}

fn parse_ports(ports_str: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for part in ports_str.split(',') {
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(start), Ok(end)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                ports.extend(start..=end);
            }
        } else if let Ok(port) = part.trim().parse::<u16>() {
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    println!("{}", "🛰️  NetScan - Network Service Scanner".bold().blue());
    println!("{}", "---------------------------------".blue());

    // 1. Always perform live host discovery (ping sweep)
    let subnet = if cli.ip.contains('/') {
        cli.ip.clone()
    } else {
        format!("{}/32", cli.ip)
    };
    println!(
        "{}",
        format!("🔎 Performing ping sweep on {subnet}...").yellow()
    );
    let live_hosts = match pingsweep::ping_sweep(&subnet).await {
        Ok(result) => {
            let hosts = result.get_live_hosts().clone();
            println!("{} live hosts found.", hosts.len());
            for h in &hosts {
                println!("  {}", h.to_string().green());
            }
            if hosts.is_empty() {
                println!("{}", "No live hosts found. Exiting.".red());
                return;
            }
            hosts
        }
        Err(e) => {
            eprintln!("Ping sweep failed: {}", e);
            return;
        }
    };

    // --- SKIP LOCAL HOST (robust version) ---
    let local_ip = match local_ip() {
        Ok(IpAddr::V4(ip)) => Some(ip),
        _ => {
            eprintln!("Could not determine local IPv4 address, skipping local host filtering.");
            None
        }
    };
    let live_hosts: Vec<Ipv4Addr> = match local_ip {
        Some(local) => live_hosts.into_iter().filter(|ip| *ip != local).collect(),
        None => live_hosts,
    };

    // --- Require user to specify ports for all scans/service-detection ---
    if cli.tcpscan || cli.udpscan || cli.service_detection || cli.fingerprint {
        if cli.ports.is_none() {
            eprintln!("You must specify --ports for scanning, fingerprinting, or service detection.");
            std::process::exit(1);
        }
    }
    // --- Require user to specify protocols for service-detection ---
    if cli.service_detection && cli.protocols.is_none() {
        eprintln!("You must specify --protocols for service detection.");
        std::process::exit(1);
    }

    // Parse ports once for all relevant operations
    let ports: Vec<u16> = cli.ports.as_ref().map(|s| parse_ports(s)).unwrap_or_default();

    // 2. Fingerprinting (if requested)
    if cli.fingerprint {
        println!("{}", "🕵️  Fingerprinting live hosts...".cyan());
        let fingerprints = futures::future::join_all(
            live_hosts
                .iter()
                .map(|&ip| fingerprinting::fingerprint_host(ip, &ports)),
        )
        .await;
        for fp in fingerprints {
            println!(
                "{}\n  {}: {}\n  {}: {}\n  {}: {}\n  {}: {}",
                format!("{}", fp.ip).bold().yellow(),
                "OS".bold().blue(),
                fp.os.as_deref().unwrap_or("Unknown").green(),
                "Vendor".bold().blue(),
                fp.vendor.as_deref().unwrap_or("Unknown").green(),
                "Serial".bold().blue(),
                fp.serial.as_deref().unwrap_or("Unknown").green(),
                "Details".bold().blue(),
                fp.details
                    .as_deref()
                    .map(|d| d.replace('\n', "\n    "))
                    .unwrap_or_else(|| "None".to_string())
                    .normal()
            );
            println!("{}", "-".repeat(60).dimmed());
        }
    }

    // 3. TCP scan (if requested)
    if cli.tcpscan {
        if !ports.is_empty() {
            let min_port = *ports.first().unwrap();
            let max_port = *ports.last().unwrap();
            let port_range = min_port..(max_port + 1); // Range<u16>
            println!("{}", "🔗 Performing TCP scan...".cyan());
            let tcp_result = tcpscan::tcp_scan(&live_hosts, port_range).await;
            tcp_result.print_summary();
        }
    }

    // 4. UDP scan (if requested)
    if cli.udpscan {
        if !ports.is_empty() {
            let min_port = *ports.first().unwrap();
            let max_port = *ports.last().unwrap();
            let port_range = min_port..(max_port + 1); // Range<u16>
            println!("{}", "🔗 Performing UDP scan...".cyan());
            let udp_result = udpscan::udp_scan(&live_hosts, port_range).await;
            udp_result.print_summary();
        }
    }

    // 5. Service detection (if requested)
    if cli.service_detection {
        let protocols: Vec<Protocol> = cli
            .protocols
            .as_ref()
            .unwrap()
            .iter()
            .map(|p| p.to_protocol())
            .collect();
        for ip in &live_hosts {
            let results =
                service_detection::service_scan(*ip, Some(ports.clone()), &protocols).await;
            prettyprint::pretty_print_service_results(
                &format!("Detected Services for {}", ip),
                &results,
            );
            let _ = rust_backend::utils::reports::append_summary_to_csv(
                "netscan_protocol_summary.csv",
                &ip.to_string(),
                &results,
            );
        }
        println!(
            "{}",
            "📄 Protocol failure summary appended to netscan_protocol_summary.csv".cyan()
        );
    }
}