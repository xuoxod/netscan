use colored::*;
use crate::scanners::service_detection;

pub fn pretty_print_service_results(
    title: &str,
    results: &[service_detection::ServiceDetectionResult],
) {
    println!("\n{}", title.bold().underline().blue());
    println!(
        "{:<8} {:<20} {:<10} {}",
        "Port".bold().cyan(),
        "Service".bold().cyan(),
        "Status".bold().cyan(),
        "Error".bold().cyan()
    );
    println!("{}", "-".repeat(70).dimmed());

    for res in results {
        let service_str = match &res.service {
            Some(s) if s == "Unknown Service" => s.red().bold(),
            Some(s) if s == "HTTP" || s == "HTTPS" => s.green().bold(),
            Some(s) => s.yellow().bold(),
            None => "-".normal(),
        };
        let status_str = if res.error.is_none() {
            "OK".green()
        } else {
            "FAIL".red()
        };
        let error_str = match &res.error {
            Some(e) if e != "-" => e.bright_red(),
            _ => "-".normal(),
        };
        println!(
            "{:<8} {:<20} {:<10} {}",
            res.port.to_string().bold(),
            service_str,
            status_str,
            error_str
        );
    }
    println!("{}", "-".repeat(70).dimmed());
    println!();
}



/// Converts a sorted Vec<u16> into a compact range string, e.g. "1-5,7,9-11"
pub fn format_port_ranges(ports: &[u16]) -> String {
    if ports.is_empty() {
        return String::new();
    }
    let mut ranges = Vec::new();
    let mut start = ports[0];
    let mut end = ports[0];

    for &port in &ports[1..] {
        if port == end + 1 {
            end = port;
        } else {
            if start == end {
                ranges.push(format!("{}", start));
            } else {
                ranges.push(format!("{}-{}", start, end));
            }
            start = port;
            end = port;
        }
    }
    // Push the last range
    if start == end {
        ranges.push(format!("{}", start));
    } else {
        ranges.push(format!("{}-{}", start, end));
    }
    ranges.join(",")
}