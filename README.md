# 🛠️ NetScan: Network Toolkit

[![Build Status](https://example.com/build-status)](https://example.com/build-status)  
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)  
[![Rust Version](https://img.shields.io/badge/Rust-1.86%2B-orange)](https://www.rust-lang.org/)  
[![Java Version](https://img.shields.io/badge/Java-23.0.2-brightgreen)](https://www.java.com/)

---

## 🧑‍💻 **Project Overview**

NetScan is a **modular network toolkit** designed to perform various **network-related tasks**. It leverages the **performance of Rust** for backend operations and the **versatility of Java** for the frontend interface. The toolkit is built with extensibility and efficiency in mind, making it suitable for a wide range of network tasks.

---

## 🖥️ Java Frontend

NetScan includes a Java-based terminal frontend that communicates with the Rust backend via JNA (Java Native Access).

- The Java frontend provides a terminal interface for configuring scans, viewing results, and managing tasks.
- See the java_frontend directory for source code and build instructions.

---

## 🦀 Rust Backend

The Rust backend provides the core scanning, detection, and fingerprinting logic. It exposes a command-line interface (CLI) and can also be called from the Java frontend via FFI.

- High-performance, safe, and concurrent network operations.
- Exposes all major features (ping sweep, port scan, service detection, fingerprinting) via CLI and FFI.
- See the `rust_backend/` directory for source code, tests, and build instructions.

## 🧰 Features

- Fast ping sweep (ICMP)
- TCP/UDP port scanning
- Service detection (SSH, HTTP, FTP, etc.)
- MAC address fingerprinting
- Modular and extensible design
- Cross-platform (Linux, macOS, Windows)

---

## 🎯 **Goals**

1. **Modular Design**: Support multiple network-related tasks (e.g., scanning, monitoring, etc.).
2. **Accurate TCP Port Scanning**: Identify open ports on specified targets.
3. **Flexible Target Specification**: Support single IPs, ranges, and CIDR blocks.
4. **Customizable Port Selection**: Scan specific ports or ranges.
5. **Clear Console Output**: Display results in an easy-to-read format.
6. **Separation of Concerns**: Maintain a clean distinction between Rust backend logic and Java frontend interface.
7. **Future Extensions**: Explore UDP scanning, service banner grabbing, and other network utilities.

---

## 🚀 Getting Started

1. **Clone the repo:**  

   git clone https://github.com/xuoxod/netscan.git

2. **Build the Rust backend:**

   cd netscan/rust_backend && cargo build --release

3. **Run a scan:**

   sudo ./target/release/netscan --ip 192.168.1.1 --tcpscan --ports 22,80

---

---

## 📝 Usage Examples

- **Scan a single host for SSH and HTTP:**

```sh
  Fingerprint a host:
  sudo ./netscan --ip 192.168.1.158 --tcpscan --ports 22,80 --protocols ssh,http --service-detection

  Full TCP scan for common ports:
  sudo ./netscan --ip 192.168.1.158 --tcpscan --ports 21,22,23,25,53,80,110,443

  Service detection for DNS and HTTP:
  sudo ./netscan --ip 192.168.1.1 --ports 53,80 --protocols dns,http --service-detection
```

---

## 🖨️ Sample Output

Here’s what a typical scan result looks like:

```plaintext
🛰️  NetScan - Network Service Scanner
---------------------------------
🔎 Performing ping sweep on 192.168.1.158/32...
1 live hosts found.
  192.168.1.158
🔗 Performing TCP scan...
TCP scan completed.
Total open ports: 1
Total errors: 30756

Detected Services for 192.168.1.158
Port     Service              Status     Error
----------------------------------------------------------------------
30778    SSH                  OK         -
22       Unknown Service      FAIL       Connection failed | Connection failed
80       Unknown Service      FAIL       Connection failed | Connection failed
----------------------------------------------------------------------
📄 Protocol failure summary appended to netscan_protocol_summary.csv
```

## 💻 **Requirements**

### **Runtime**

- 🖥️ **Java Runtime Environment (JRE)**: Version **11+**
- ⚙️ **Rust Compiler**: Version **1.70+**

### **Build Tools**

- 🛠️ **Maven**: Version **3.6+**
- 📦 **Cargo**: Rust's package manager.

### **Operating System**

- 🐧 **Linux**: Ubuntu recommended for script compatibility.
- 🍎 **macOS**: Supported with `.dylib` shared libraries.
- 🪟 **Windows**: Supported with `.dll` shared libraries.

### **Environment**

- 🐚 **Bash Shell**: Required for setup and utility scripts.

---

## 📦 **Dependencies**

### **Java**

- **JNA (Java Native Access)**: Version **5.14.0**  
  Used for seamless communication between Java and Rust.  
  [JNA Documentation](https://github.com/java-native-access/jna)

### **Rust**

- **Rust Networking Crates**:  
  - `std::net`: For basic networking operations.  
  - `tokio` (optional): For asynchronous scanning.  
  [Tokio Documentation](https://tokio.rs/)

---

```markdown
## 📂 **Project Directory Structure**

A typical layout for this project:

  ```plaintext
  netscan.
    ├── java_frontend/         # Java CLI and interface code
    │   └── src/...
    ├── rust_backend/          # Rust backend (CLI, core logic, FFI)
    │   ├── src/...
    │   └── tests/...
    ├── scripts/               # Helper scripts
    ├── [setup.sh](http://_vscodecontentref_/3)               # Project setup script
    ├── [README.md](http://_vscodecontentref_/4)
    └── ...

---

## 🧪 Test Suite & Expected Behaviors

This project includes comprehensive integration and unit tests for all major modules.

### Service Detection Tests

- **test_service_scan**: Verifies that all specified ports are scanned and results are returned for each.
- **test_service_scan_default**: Ensures that when no ports are specified, the default range (0..=1024) is scanned.
- **test_detect_service_http/https/ssh/ftp/smtp/pop3**: Confirms that the correct protocol is detected on standard ports, or "Unknown Service" is returned if not detected.
- **test_detect_service_non_traditional_ssh**: Checks detection of SSH on a non-standard port.
- **test_detect_service_unknown**: Ensures that unknown or closed ports are reported as "Unknown Service".

### TCP/UDP Scan Tests

- **test_tcp_scan_valid_host**: Scans a valid host and expects open/closed port results.
- **test_tcp_scan_invalid_host**: Handles invalid hosts gracefully.
- **test_tcp_scan_empty_port_range**: Returns no results for an empty port list.

### Pingsweep Tests

- **test_ping_sweep_valid_subnet**: Discovers live hosts in a valid subnet.
- **test_ping_sweep_invalid_subnet**: Handles invalid subnet input gracefully.

### MAC Fingerprinting Tests

- **test_fingerprint_mac_on_localhost**: Ensures the MAC fingerprinting function does not panic and returns a result for localhost.

**All tests are designed to be robust, clear, and easy to extend. See the `/tests` directory for details.**

---

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

- If you add a new protocol or feature, please include corresponding tests.
- Document any assumptions or requirements for your tests.
- Open an issue or pull request if you have suggestions or bug reports.

---

## 📝 License

This project is licensed under the MIT License.  
See the [LICENSE](LICENSE) file for details.
