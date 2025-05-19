# 🛠️ NetScan: Network Toolkit

[![Build Status](https://example.com/build-status)](https://example.com/build-status)  
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)  
[![Rust Version](https://img.shields.io/badge/Rust-1.86%2B-orange)](https://www.rust-lang.org/)  
[![Java Version](https://img.shields.io/badge/Java-23.0.2-brightgreen)](https://www.java.com/)

---

## 🧑‍💻 **Project Overview**

NetScan is a **modular network toolkit** designed to perform various **network-related tasks**. It leverages the **performance of Rust** for backend operations and the **versatility of Java** for the frontend interface. The toolkit is built with extensibility and efficiency in mind, making it suitable for a wide range of network tasks.

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

## 📂 **Project Directory Structure**

The following represents the **bare-minimum structure** required for this project:

    ```plaintext
    [4.0K]  .
    ├── [6.5K]  [setup.sh](https://github.com/xuoxod/netscan.git)          # Main setup script for initializing the project
    ├── [3.9K]  [README.md](https://github.com/xuoxod/netscan.git)         # Project documentation
    └── [4.0K]  scripts           # Scripts directory for utilities and helpers
        ├── [4.0K]  start         # Scripts to start the application
        ├── [4.0K]  utils         # Utility scripts
        │   ├── [4.0K]  constants # Constants used across the project
        │   ├── [4.0K]  purgers   # Scripts for cleaning/purging resources
        │   └── [4.0K]  validators # Scripts for validation tasks
        └── [4.0K]  helpers       # Helper scripts for additional functionality
# netscan

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