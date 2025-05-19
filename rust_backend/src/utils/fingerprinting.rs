use crate::detect_dns;
use crate::detect_ftp;
use crate::detect_http;
use crate::detect_smtp;
use crate::detect_ssh;
use crate::fingerprint_mac;
use std::net::Ipv4Addr;

#[derive(Debug, Clone)]
pub struct HostFingerprintResult {
    pub ip: Ipv4Addr,
    pub details: Option<String>,
    pub os: Option<String>,
    pub vendor: Option<String>,
    pub serial: Option<String>,
}

impl HostFingerprintResult {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            details: None,
            os: None,
            vendor: None,
            serial: None,
        }
    }
}

pub async fn fingerprint_host(ip: Ipv4Addr, ports: &[u16]) -> HostFingerprintResult {
    let mut result = HostFingerprintResult::new(ip);

    // MAC fingerprinting
    let mac = fingerprint_mac::fingerprint(ip).await;
    if let Some(mac_addr) = mac.mac {
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!("\nMAC: {}", mac_addr));
    }
    if let Some(vendor) = mac.vendor {
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!(" (Vendor: {})", vendor));
    }
    if let Some(mac_err) = mac.error {
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!("\nMAC error: {}", mac_err));
    }

    // SSH detection on all user-supplied ports
    for &port in ports {
        let ssh = detect_ssh::detect(ip, port).await;
        if ssh.detected {
            result
                .details
                .get_or_insert_with(String::new)
                .push_str(&format!(
                    "\nSSH detected on port {}: {}",
                    port,
                    ssh.banner.unwrap_or_default()
                ));
        }
    }

    // DNS detection on all user-supplied ports
    for &port in ports {
        let dns = detect_dns::detect(ip, port).await;
        if dns.detected {
            result
                .details
                .get_or_insert_with(String::new)
                .push_str(&format!("\nDNS detected on port {}", port));
        }
    }

    // HTTP detection on all user-supplied ports
    for &port in ports {
        let http = detect_http::detect(ip, port).await;
        if http.detected {
            result
                .details
                .get_or_insert_with(String::new)
                .push_str(&format!(
                    "\nHTTP detected on port {}: {}",
                    port,
                    http.banner.unwrap_or_default()
                ));
        }
    }

    // SMTP detection on all user-supplied ports
    for &port in ports {
        let smtp = detect_smtp::detect(ip, port).await;
        if smtp.detected {
            result
                .details
                .get_or_insert_with(String::new)
                .push_str(&format!(
                    "\nSMTP detected on port {}: {}",
                    port,
                    smtp.banner.unwrap_or_default()
                ));
        }
    }

    // FTP detection on all user-supplied ports
    for &port in ports {
        let ftp = detect_ftp::detect(ip, port).await;
        if ftp.detected {
            result
                .details
                .get_or_insert_with(String::new)
                .push_str(&format!(
                    "\nFTP detected on port {}: {}",
                    port,
                    ftp.banner.unwrap_or_default()
                ));
        }
    }

    result
}
