/// Represents a discovered service on a host.
pub struct ServiceInfo {
    pub port: u16,
    pub service: String,
    pub banner: Option<String>,
}

/// Represents a suggested Metasploit module for a service.
pub struct ModuleSuggestion {
    pub port: u16,
    pub service: String,
    pub module: String,
}

/// Suggest Metasploit modules for a list of discovered services.
/// This is a stub; mapping logic will be added next.
pub fn suggest_modules(services: &[ServiceInfo]) -> Vec<ModuleSuggestion> {
    // Placeholder: always returns empty for now.
    Vec::new()
}