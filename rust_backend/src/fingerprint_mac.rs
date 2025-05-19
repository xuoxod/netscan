use std::net::Ipv4Addr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacFingerprint {
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub error: Option<String>,
}

pub async fn fingerprint(ip: Ipv4Addr) -> MacFingerprint {
    // Placeholder: implement ARP or use a crate like `pnet` or `mac_address`
    MacFingerprint {
        mac: None,
        vendor: None,
        error: Some("Not implemented".to_string()),
    }
}