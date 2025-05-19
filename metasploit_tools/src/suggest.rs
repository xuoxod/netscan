//! # Metasploit Suggestion API
//!
//! This module provides functions to suggest relevant Metasploit modules
//! for discovered network services. Results can be exported as JSON for
//! easy integration with Java or other frontends.
//!
//! ## Example
//! ```rust
//! use metasploit_tools::suggest::{ServiceInfo, suggest_modules, suggestions_to_json};
//!
//! let services = vec![
//!     ServiceInfo { port: 22, service: "ssh".to_string(), banner: None },
//!     ServiceInfo { port: 80, service: "http".to_string(), banner: None },
//! ];
//! let suggestions = suggest_modules(&services);
//! let json = suggestions_to_json(&suggestions);
//! println!("{}", json);
//! ```

// ...existing code...




use serde::Serialize;
use serde_json;

#[derive(Serialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
}

#[derive(Serialize)]
pub struct ModuleSuggestion {
    pub port: u16,
    pub service: String,
    pub module: String,
}

pub fn suggestions_to_json(suggestions: &[ModuleSuggestion]) -> String {
    serde_json::to_string_pretty(suggestions).unwrap_or_else(|_| "[]".to_string())
}

/// Suggest Metasploit modules for a list of discovered services.
pub fn suggest_modules(services: &[ServiceInfo]) -> Vec<ModuleSuggestion> {
    // Simple static mapping for demonstration.
    let mut suggestions = Vec::new();
    
    for s in services {
        let module = match s.service.to_lowercase().as_str() {
            "ssh" => Some("auxiliary/scanner/ssh/ssh_version"),
            "http" => Some("auxiliary/scanner/http/http_version"),
            "https" => Some("auxiliary/scanner/http/http_version"),
            "smb" | "microsoft-ds" => Some("exploit/windows/smb/ms17_010_eternalblue"),
            "ftp" => Some("auxiliary/scanner/ftp/ftp_version"),
            "smtp" => Some("auxiliary/scanner/smtp/smtp_version"),
            "pop3" => Some("auxiliary/scanner/pop3/pop3_version"),
            "imap" => Some("auxiliary/scanner/imap/imap_version"),
            "mysql" => Some("auxiliary/scanner/mysql/mysql_version"),
            "mssql" => Some("auxiliary/scanner/mssql/mssql_ping"),
            "postgresql" | "postgres" => Some("auxiliary/scanner/postgres/postgres_version"),
            "rdp" | "ms-wbt-server" => Some("auxiliary/scanner/rdp/rdp_scanner"),
            "telnet" => Some("auxiliary/scanner/telnet/telnet_version"),
            "snmp" => Some("auxiliary/scanner/snmp/snmp_enum"),
            "oracle" => Some("auxiliary/scanner/oracle/tnslsnr_version"),
            "redis" => Some("auxiliary/scanner/redis/redis_server"),
            "vnc" => Some("auxiliary/scanner/vnc/vnc_none_auth"),
            "ldap" => Some("auxiliary/scanner/ldap/ldap_search"),
            _ => None,
        };

        if let Some(module) = module {
            suggestions.push(ModuleSuggestion {
                port: s.port,
                service: s.service.clone(),
                module: module.to_string(),
            });
        }
    }
    suggestions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suggest_modules_basic() {
        let services = vec![
            ServiceInfo {
                port: 22,
                service: "ssh".to_string(),
                banner: None,
            },
            ServiceInfo {
                port: 80,
                service: "http".to_string(),
                banner: None,
            },
            ServiceInfo {
                port: 445,
                service: "microsoft-ds".to_string(),
                banner: None,
            },
            ServiceInfo {
                port: 21,
                service: "ftp".to_string(),
                banner: None,
            },
            ServiceInfo {
                port: 3306,
                service: "mysql".to_string(),
                banner: None,
            },
        ];
        let suggestions = suggest_modules(&services);
        assert_eq!(suggestions.len(), 4);
        assert_eq!(suggestions[0].module, "auxiliary/scanner/ssh/ssh_version");
        assert_eq!(suggestions[1].module, "auxiliary/scanner/http/http_version");
        assert_eq!(
            suggestions[2].module,
            "exploit/windows/smb/ms17_010_eternalblue"
        );
        assert_eq!(suggestions[3].module, "auxiliary/scanner/ftp/ftp_version");
    }
}
