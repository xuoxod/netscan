use rust_backend::scanners::pingsweep::ping_sweep;
use rust_backend::scanners::tcpscan::tcp_scan;
use rust_backend::utils::prettyprint::{pretty_print_collection, pretty_print_summary};
use tokio::runtime::Runtime;

fn main() {
    let rt = Runtime::new().expect("Failed to create Tokio runtime");
    let subnet = "192.168.1.0/24"; // Example subnet for testing
    let port_range = 1..1024; // Common ports to scan

    // Perform a ping sweep
    let ping_result = rt.block_on(ping_sweep(subnet)).unwrap();
    pretty_print_collection("Live Hosts", ping_result.get_live_hosts(), "32"); // Green
    pretty_print_summary(ping_result.get_live_hosts().len(), ping_result.get_not_alive_hosts().len());

    // Perform a TCP port scan on live hosts
    let tcp_result = rt.block_on(tcp_scan(ping_result.get_live_hosts(), port_range));
    pretty_print_collection("Open Ports", tcp_result.get_open_ports(), "34"); // Blue
    tcp_result.print_summary();
}