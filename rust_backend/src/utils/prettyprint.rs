use colored::*;

/// Pretty print any collection (existing function, unchanged)
pub fn pretty_print_collection<T: std::fmt::Debug>(title: &str, collection: &[T], color: &str) {
    println!("\x1b[1;{}m{}\x1b[0m", color, title);
    for (i, item) in collection.iter().enumerate() {
        println!("\x1b[{}m{:>3}: {:?}\x1b[0m", color, i + 1, item);
    }
    println!();
}

/// Pretty print a summary of live/not-alive hosts (existing function, unchanged)
pub fn pretty_print_summary(live_count: usize, not_alive_count: usize) {
    println!("\x1b[1;32mLive Hosts: {}\x1b[0m", live_count);
    println!("\x1b[1;31mNot Alive Hosts: {}\x1b[0m", not_alive_count);
}

/// Pretty print service detection results in a uniform, colorized table
pub fn pretty_print_service_results(title: &str, results: &[crate::scanners::service_detection::ServiceDetectionResult]) {
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