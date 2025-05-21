use crate::detect_dns;
use crate::detect_ftp;
use crate::detect_http;
use crate::detect_smtp;
use crate::detect_ssh;
use crate::fingerprint_mac;
use crate::scanners::pingsweep::{LiveHost, guess_os_from_ttl};
use std::net::Ipv4Addr;
use tokio::time::{Duration, sleep};

#[derive(Debug, Clone)]
pub struct HostFingerprintResult {
    pub ip: Ipv4Addr,
    pub details: Option<String>,
    pub os: Option<String>,
    pub vendor: Option<String>,
    pub serial: Option<String>,
    pub mac: Option<String>,
}

impl HostFingerprintResult {
    pub fn new(ip: Ipv4Addr) -> Self {
        Self {
            ip,
            details: None,
            os: None,
            vendor: None,
            serial: None,
            mac: None,
        }
    }
}

/// Accepts a LiveHost (with ip and ttl) for OS guessing and MAC/vendor detection.
pub async fn fingerprint_host(live_host: &LiveHost, ports: &[u16]) -> HostFingerprintResult {
    // Add a delay so in-place console update is visible
    sleep(Duration::from_millis(700)).await;

    let mut result = HostFingerprintResult::new(live_host.ip);

    // OS Guess from TTL
    if let Some(ttl) = live_host.ttl {
        let os_guess = guess_os_from_ttl(ttl);
        result.os = Some(os_guess.to_string());
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!("\nOS guess from TTL {}: {}", ttl, os_guess));
    }

    // MAC fingerprinting
    let mac_fp = fingerprint_mac::fingerprint(live_host.ip).await;
    if let Some(mac_addr) = mac_fp.mac {
        result.mac = Some(mac_addr.to_string());
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!("\nMAC: {}", mac_addr));
    }
    if let Some(vendor) = mac_fp.vendor {
        result.vendor = Some(vendor.clone());
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!(" (Vendor: {})", vendor));
    }
    if let Some(mac_err) = mac_fp.error {
        result
            .details
            .get_or_insert_with(String::new)
            .push_str(&format!("\nMAC error: {}", mac_err));
    }

    // SSH detection on all user-supplied ports
    for &port in ports {
        let ssh = detect_ssh::detect(live_host.ip, port).await;
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
        let dns = detect_dns::detect(live_host.ip, port).await;
        if dns.detected {
            result
                .details
                .get_or_insert_with(String::new)
                .push_str(&format!("\nDNS detected on port {}", port));
        }
    }

    // HTTP detection on all user-supplied ports
    for &port in ports {
        let http = detect_http::detect(live_host.ip, port).await;
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
        let smtp = detect_smtp::detect(live_host.ip, port).await;
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
        let ftp = detect_ftp::detect(live_host.ip, port).await;
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
