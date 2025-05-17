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