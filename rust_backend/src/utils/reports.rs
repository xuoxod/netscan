use std::collections::HashMap;
use std::fs::OpenOptions;
use std::io::Write;
use chrono::Utc;
use crate::scanners::service_detection; // <-- Use the crate name

pub fn append_summary_to_csv(
    filename: &str,
    ip: &str,
    results: &[service_detection::ServiceDetectionResult], // <-- Use the module path
) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(filename)?;

    // Aggregate protocol failures
    let mut protocol_counts: HashMap<String, Vec<u16>> = HashMap::new();
    for res in results {
        for proto in &res.protocol_failures {
            protocol_counts.entry(proto.clone()).or_default().push(res.port);
        }
    }

    writeln!(file, "Timestamp,Target,Protocol,FailCount,Ports")?;
    for (proto, ports) in protocol_counts {
        writeln!(
            file,
            "{},{},{},{},\"{}\"",
            Utc::now().to_rfc3339(),
            ip,
            proto,
            ports.len(),
            ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",")
        )?;
    }
    Ok(())
}