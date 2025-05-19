use metasploit_tools::suggest::{ServiceInfo, suggest_modules, suggestions_to_json};

fn main() {
    // Example: hardcoded scan results
    let services = vec![
        ServiceInfo {
            port: 22,
            service: "ssh".to_string(),
            banner: Some("OpenSSH 8.2".to_string()),
        },
        ServiceInfo {
            port: 80,
            service: "http".to_string(),
            banner: Some("Apache".to_string()),
        },
        ServiceInfo {
            port: 445,
            service: "microsoft-ds".to_string(),
            banner: None,
        },
        ServiceInfo {
            port: 21,
            service: "ftp".to_string(),
            banner: Some("vsftpd".to_string()),
        },
        ServiceInfo {
            port: 3306,
            service: "mysql".to_string(),
            banner: None,
        },
    ];

    let suggestions = suggest_modules(&services);

    println!("Metasploit module suggestions:");
    for s in suggestions {
        println!("Port {} ({}): {}", s.port, s.service, s.module);
    }

    let suggestions = suggest_modules(&services);

    println!("Metasploit module suggestions:");
    for s in &suggestions {
        println!("Port {} ({}): {}", s.port, s.service, s.module);
    }

    // Print as JSON for frontend consumption
    println!("\nJSON output:");
    println!("{}", suggestions_to_json(&suggestions));
}
