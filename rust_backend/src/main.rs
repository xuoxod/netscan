use clap::Parser;
use colored::*;
use rust_backend::scanners::service_detection;
use rust_backend::utils::reports;

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
    netscan --ip 127.0.0.1 --ports 1-1024

For more information, visit: https://github.com/yourproject/netscan
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
        short,
        long,
        value_name = "PORTS",
        help = "Ports to scan (comma-separated or ranges, e.g. 22,80,443,1000-1010)"
    )]
    ports: Option<String>,
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
    }

    // Call your async service scan (update this path if needed)
    let results = service_detection::service_scan(ip, Some(ports.clone())).await;

    print_detected_services_and_summary(&results);

    if let Err(e) =
        reports::append_summary_to_csv("netscan_protocol_summary.csv", &cli.ip, &results)
    {
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

// Print detected services and a concise summary, with colors and emojis
fn print_detected_services_and_summary(results: &[service_detection::ServiceDetectionResult]) {
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
        // Collect protocol failures for summary
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
            ports
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(",")
                .yellow()
        );
    }
}
