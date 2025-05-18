use clap::{Parser, ValueEnum};
use colored::*;
use rust_backend::scanners::service_detection::{self, Protocol, ServiceDetectionResult};

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
    pub fn as_protocol(&self) -> Protocol {
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
    about = "A fast, flexible, and extensible network service scanner.",
    long_about = None,
    after_help = "\
EXAMPLES:
    netscan --ip 192.168.1.1
    netscan --ip 10.0.0.5 --ports 22,80,443,8080
    netscan --ip 127.0.0.1 --ports 1-1024 --protocols ssh,ftp
    netscan --ip 127.0.0.1 --protocols smtp

Protocols: ssh, ftp, smtp, http, https, dns, pop3, imap, telnet (more coming soon!)
"
)]
pub struct Cli {
    #[arg(
        short,
        long,
        value_name = "IP",
        help = "Target IPv4 address (e.g., 192.168.1.1)"
    )]
    ip: String,
    #[arg(
        short = 'p',
        long,
        value_name = "PORTS",
        help = "Ports to scan (comma-separated or ranges, e.g. 22,80,443,1000-1010)"
    )]
    ports: Option<String>,
    #[arg(
        short = 'r',
        long,
        value_name = "PROTOCOLS",
        value_enum,
        use_value_delimiter = true,
        help = "Protocols to detect (comma-separated, e.g. ssh,ftp,smtp)"
    )]
    protocols: Option<Vec<ProtocolArg>>,
    #[arg(short, long, help = "Enable verbose output")]
    verbose: bool,
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

    let ip: std::net::Ipv4Addr = match cli.ip.parse() {
        Ok(ip) => ip,
        Err(_) => {
            eprintln!("{}", "❌ Invalid IP address format!".red().bold());
            std::process::exit(1);
        }
    };

    let ports: Vec<u16> = match &cli.ports {
        Some(ports_str) => parse_ports(ports_str),
        None => (1..=1024).collect(), // Default: scan well-known ports
    };

    let protocols: Vec<Protocol> = cli
        .protocols
        .as_ref()
        .map(|vec| vec.iter().map(|p| p.as_protocol()).collect())
        .unwrap_or_else(|| vec![Protocol::Ssh, Protocol::Ftp, Protocol::Smtp]);

    if cli.verbose {
        println!("{}", "🔎 Verbose mode enabled".yellow());
        println!("Target: {}", ip.to_string().cyan());
        println!(
            "Ports: {}",
            ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
                .yellow()
        );
        println!(
            "Protocols: {}",
            protocols
                .iter()
                .map(|p| format!("{:?}", p))
                .collect::<Vec<_>>()
                .join(", ")
                .yellow()
        );
    }

    let results = service_detection::service_scan(ip, Some(ports.clone()), &protocols).await;

    print_detected_services_and_summary(&results);

    if let Err(e) = rust_backend::utils::reports::append_summary_to_csv(
        "netscan_protocol_summary.csv",
        &cli.ip,
        &results,
    ) {
        eprintln!(
            "{} Failed to append to protocol summary: {}",
            "Error:".red(),
            e
        );
    } else {
        println!(
            "{}",
            "📄 Protocol failure summary appended to netscan_protocol_summary.csv".cyan()
        );
    }
}

fn print_detected_services_and_summary(results: &[ServiceDetectionResult]) {
    use std::collections::HashMap;

    println!("\n{}", "🔬 Detected Services:".bold().green());
    println!(
        "{:<8} {:<20} {:<8} {}",
        "Port".bold().blue(),
        "Service".bold().blue(),
        "Status".bold().blue(),
        "Error".bold().blue()
    );
    println!("{}", "-".repeat(70).blue());

    let mut detected = 0;
    let mut ok = 0;
    let mut fail = 0;
    let mut protocol_failures: HashMap<String, Vec<u16>> = HashMap::new();

    for r in results {
        if r.service.as_deref() != Some("Unknown Service") {
            detected += 1;
            let status = if r.error.is_none() {
                ok += 1;
                "✅ OK".green()
            } else {
                fail += 1;
                "❌ FAIL".red()
            };
            println!(
                "{:<8} {:<20} {:<8} {}",
                r.port.to_string().yellow(),
                r.service.as_deref().unwrap_or("-").bold(),
                status,
                r.error.as_deref().unwrap_or("-").red()
            );
        }
        for proto in &r.protocol_failures {
            protocol_failures
                .entry(proto.clone())
                .or_default()
                .push(r.port);
        }
    }

    println!("\n{}", "📊 Summary:".bold().magenta());
    println!(
        "  {} ports scanned, {} detected, {} OK, {} FAIL",
        results.len().to_string().cyan(),
        detected.to_string().green(),
        ok.to_string().green(),
        fail.to_string().red()
    );

    println!("{}", "\n🚦 Protocol Failure Counts:".bold().yellow());
    for (proto, ports) in protocol_failures {
        println!(
            "  {} failed on {} ports: {}",
            proto.bold().red(),
            ports.len().to_string().red(),
            rust_backend::utils::prettyprint::format_port_ranges(&{
                let mut sorted = ports.clone();
                sorted.sort_unstable();
                sorted
            })
            .yellow()
        );
    }
}
