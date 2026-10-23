# Basic Network Sniffer using Python & Scapy

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Scapy Version](https://img.shields.io/badge/scapy-2.8.0-green.svg)
![Tests](https://img.shields.io/badge/tests-22%20passed-brightgreen.svg)
![Internship Task](https://img.shields.io/badge/CodeAlpha-Cyber%20Security-darkblue.svg)
![License](https://img.shields.io/badge/license-MIT-lightgrey.svg)

An educational, beginner-friendly network packet sniffer developed using **Python** and **Scapy**. This project was created as part of the **CodeAlpha Cyber Security Internship** to demonstrate fundamental computer networking, packet inspection, protocol analysis, and ethical security practices.

---

## 📌 Project Objectives

1. **Packet Capture & Decoding**: Intercept and inspect Layer 2, Layer 3, and Layer 4 packets passing through network interfaces.
2. **Metadata Extraction**: Parse timestamps, source/destination IP addresses, protocol types, TCP/UDP ports, packet lengths, and sanitized payload previews.
3. **Data Logging**: Stream captured packet metrics into a structured CSV format for offline incident analysis and reporting.
4. **Privacy & Security by Design**: Prevent accidental collection of sensitive user credentials, session tokens, or private secrets using automated payload sanitization and redaction.
5. **Robust Testability**: Provide 100% offline testability via synthetic packet generation, allowing comprehensive testing without administrative (`root`/`sudo`) privileges or live network dependencies.

---

## ⚙️ Key Features

- **Multi-Protocol Inspection**:
  - **Layer 2 (Data Link)**: ARP request/reply frames, Ethernet MAC details.
  - **Layer 3 (Network)**: IPv4 and IPv6 packet headers.
  - **Layer 4 (Transport)**: TCP (with sequence/acknowledgment tracking), UDP, ICMP (Echo Ping).
  - **Application Identification**: Automatic DNS query/response detection.
- **Payload Sanitization & Security**:
  - Automatically replaces non-printable binary characters with dots (`.`) similar to standard hexdump utilities.
  - Redacts sensitive credentials (e.g., `password=`, `api_key=`, `bearer `, `authorization:`, `set-cookie:`) from previews to adhere to data privacy standards.
- **Command-Line Interface (CLI)**:
  - Interface selection (`-i / --interface`).
  - Packet count limiter (`-c / --count`).
  - Berkeley Packet Filter (BPF) syntax support (`-f / --filter`).
  - Structured CSV export (`-o / --output`).
  - Network interface enumeration (`-l / --list-interfaces`).
  - Safe offline demonstration mode (`--sample`).
- **Resilience & Defensive Architecture**:
  - Catches missing device handle permissions (`/dev/bpf` on macOS) and displays actionable, friendly guidance.
  - Graceful shutdown upon `Ctrl+C` with detailed capture statistics (total packets, byte count, protocol distribution).
  - Defensive monkeypatching for restricted environments where `/etc/resolv.conf` cannot be accessed.

---

## 📋 Prerequisites

- **Operating System**: macOS, Linux, or Windows.
- **Python**: Version 3.10 or later (tested on Python 3.14).
- **Permissions**:
  - **Live packet capture**: Requires administrative privileges (`sudo` on macOS/Linux, Administrator on Windows) to access raw sockets or `/dev/bpf` capture handles.
  - **Offline testing / synthetic simulation**: Requires **no administrative privileges** and runs in standard user space.

---

## 🚀 Installation & Setup

### 1. Navigate to Project Directory
```bash
cd basic-network-sniffer
```

### 2. Create and Activate Virtual Environment
```bash
# Create virtual environment
python3 -m venv .venv

# Activate on macOS / Linux:
source .venv/bin/activate

# Or activate on Windows:
# .venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

Verify installation:
```bash
python -c "import scapy; print('Scapy version:', scapy.__version__)"
# Output: Scapy version: 2.8.0
```

---

## 🖥️ Usage Instructions

### 1. View Help and Options
```bash
python sniffer.py --help
```

### 2. List Available Network Interfaces
```bash
python sniffer.py --list-interfaces
```
*Output:*
```text
Available Network Interfaces:
----------------------------------------
   1. en0
   2. en1
   3. lo0
   ...
----------------------------------------
Tip: Use '-i <interface_name>' to specify the capture interface.
```

### 3. Safe Offline Demonstration Mode (No `sudo` required)
Run synthetic packet simulation to verify all decoding and logging features without administrative rights:
```bash
python sniffer.py --sample -c 10 -o sample_capture.csv
```

### 4. Live Packet Capture (Requires Administrative Privileges)
> [!IMPORTANT]
> Live network sniffing requires access to raw sockets (`sudo` on macOS / Linux).

#### Basic Live Capture (Captures until `Ctrl+C`):
```bash
sudo ./.venv/bin/python sniffer.py -i en0
```

#### Capture a Fixed Number of Packets (e.g., 20 packets):
```bash
sudo ./.venv/bin/python sniffer.py -i en0 -c 20
```

#### Apply Berkeley Packet Filters (BPF):
- **Only HTTP/HTTPS Traffic**:
  ```bash
  sudo ./.venv/bin/python sniffer.py -i en0 -f "tcp port 80 or tcp port 443"
  ```
- **Only DNS Traffic**:
  ```bash
  sudo ./.venv/bin/python sniffer.py -i en0 -f "udp port 53"
  ```
- **Only ICMP (Ping) Packets**:
  ```bash
  sudo ./.venv/bin/python sniffer.py -i en0 -f "icmp"
  ```

#### Export Capture Data to CSV:
```bash
sudo ./.venv/bin/python sniffer.py -i en0 -c 50 -o live_capture.csv
```

---

## 🧪 Automated Testing

A comprehensive unit test suite is included in `test_sniffer.py`. The suite validates all core components using synthetic packets in memory—requiring **zero root access or live network connections**.

### Running the Test Suite:
```bash
python -m unittest test_sniffer.py -v
```

### Test Coverage Highlights:
- `test_parse_tcp_packet`: Verifies IPv4, TCP flags, ports, and payload extraction.
- `test_parse_udp_packet`: Verifies UDP datagram parsing.
- `test_parse_dns_packet`: Verifies DNS recognition over port 53.
- `test_parse_icmp_packet`: Verifies ICMP Echo (Ping) handling.
- `test_parse_arp_packet`: Verifies Layer 2 ARP frames.
- `test_parse_ipv6_packet`: Verifies IPv6 next-generation network headers.
- `test_credential_redaction_*`: Tests sanitization and redaction of passwords, API keys, and bearer tokens.
- `test_csv_logger_lifecycle`: Tests CSV header creation, stream writing, and flushing.
- `test_offline_simulation_mode`: Verifies full end-to-end simulation workflow.

---

## 📊 Sample Output

### Terminal Console Output:
```text
================================================================================
  CodeAlpha Cyber Security Internship: Basic Network Sniffer
================================================================================
  ETHICAL USAGE WARNING:
  Capturing network traffic without explicit authorization is illegal.
  Ensure you have permission to monitor traffic on this network.
--------------------------------------------------------------------------------
  Mode:            OFFLINE SYNTHETIC SAMPLE MODE
  Interface:       Default System Interface
  Filter (BPF):    None (all traffic)
  Packet Count:    8
  CSV Output:      sample_capture.csv
================================================================================
Sniffing started... Press Ctrl+C at any time to stop.

[*] Simulating capture of 8 synthetic test packets...

[2026-10-23 04:45:22.005] TCP   | 192.168.1.105:51234 -> 93.184.216.34:80      | Len:   126B | Preview: GET /index.html HTTP/1.1..Host: example....
[2026-10-23 04:45:22.058] TCP   | 192.168.1.105:51235 -> 142.250.190.46:443    | Len:    91B | Preview: ...........TLS_SIMULATION_PACKET_DATA
[2026-10-23 04:45:22.114] DNS   | 192.168.1.105:53001 -> 8.8.8.8:53            | Len:    74B | Preview: .4...........codealpha.tech.....
[2026-10-23 04:45:22.169] ICMP  | 192.168.1.105 -> 1.1.1.1                     | Len:    74B | Preview: abcdefghijklmnopqrstuvwabcdefghi
[2026-10-23 04:45:22.225] ARP   | 192.168.1.105 -> 192.168.1.1                 | Len:    42B | Preview: <empty>
[2026-10-23 04:45:22.280] UDP   | 192.168.1.105:48212 -> 216.239.35.0:123      | Len:    80B | Preview: #...........NTP_REQUEST_TIMESTAMP_DATA
[2026-10-23 04:45:22.333] TCP   | 2001:db8::1:60001 -> 2001:db8::2:8080        | Len:    77B | Preview: IPV6_PAYLOAD_TEST
[2026-10-23 04:45:22.389] TCP   | 192.168.1.105:49999 -> 192.168.1.200:8000    | Len:   109B | Preview: user=admin&password=[REDACTED]&action=lo...

================================================================================
  Capture Statistics Summary
================================================================================
  Total Packets Captured: 8
  Total Data Processed:   673 bytes
  Elapsed Time:           0.44 seconds

  Protocol Breakdown:
    - TCP     :     4 packets ( 50.0%)
    - DNS     :     1 packets ( 12.5%)
    - ICMP    :     1 packets ( 12.5%)
    - ARP     :     1 packets ( 12.5%)
    - UDP     :     1 packets ( 12.5%)

  [+] Capture data saved to CSV: sample_capture.csv
================================================================================
```

### Exported CSV File (`sample_capture.csv`):
| timestamp | protocol | src_ip | src_port | dst_ip | dst_port | length_bytes | payload_preview |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `2026-10-23 04:45:22.005` | TCP | `192.168.1.105` | 51234 | `93.184.216.34` | 80 | 126 | `GET /index.html HTTP/1.1..Host: example....` |
| `2026-10-23 04:45:22.058` | TCP | `192.168.1.105` | 51235 | `142.250.190.46` | 443 | 91 | `...........TLS_SIMULATION_PACKET_DATA` |
| `2026-10-23 04:45:22.114` | DNS | `192.168.1.105` | 53001 | `8.8.8.8` | 53 | 74 | `.4...........codealpha.tech.....` |
| `2026-10-23 04:45:22.169` | ICMP | `192.168.1.105` | N/A | `1.1.1.1` | N/A | 74 | `abcdefghijklmnopqrstuvwabcdefghi` |
| `2026-10-23 04:45:22.225` | ARP | `192.168.1.105` | N/A | `192.168.1.1` | N/A | 42 | `<empty>` |
| `2026-10-23 04:45:22.389` | TCP | `192.168.1.105` | 49999 | `192.168.1.200` | 8000 | 109 | `user=admin&password=[REDACTED]&action=lo...` |

---

## 🔒 Ethical Considerations & Legal Compliance

As cybersecurity professionals, packet capture tools must be used strictly in accordance with ethical standards and legal requirements:

1. **Authorization**: Never capture packets on any network without prior written authorization from the network owner or administrator.
2. **Privacy Protection**: In transit packet payloads often contain personal or sensitive data. This sniffer explicitly:
   - Restricts payload previews to a short prefix.
   - Automatically masks passwords, auth tokens, cookies, and keys.
   - Discourages sniffing on public networks.
3. **Legal Compliance**: Unauthorized packet interception violates laws such as:
   - **United States**: Computer Fraud and Abuse Act (CFAA), Electronic Communications Privacy Act (ECPA).
   - **India**: Information Technology Act (IT Act 2000 / 2008), Section 43 & Section 66.
   - **European Union**: General Data Protection Regulation (GDPR) and ePrivacy Directive.
4. **Academic Purpose**: This software was written strictly for educational purposes within the CodeAlpha Cyber Security Internship.

---

## ⚠️ Technical Limitations

- **Switched Networks**: On switched modern LANs, an interface will only see unicast packets addressed to its own MAC address, plus broadcast and multicast traffic. Viewing traffic of other network nodes requires port mirroring (SPAN) or hub environments.
- **Encrypted Traffic**: Standard encrypted application payloads (TLS/HTTPS, SSH, IPsec) cannot be inspected in plaintext without endpoint SSL termination or session key secrets.
- **High-Throughput Environments**: Python and Scapy are designed for rapid prototyping and education. For multi-gigabit line-rate packet analysis in production, native compiled tools such as Wireshark/TShark, tcpdump, or Zeek/Suricata with DPDK/eBPF are recommended.

---

## 📁 Repository Structure

```text
basic-network-sniffer/
├── .gitignore               # Git exclusions for venv, cache, and pcaps
├── README.md                # Comprehensive project documentation
├── SUBMISSION_CHECKLIST.md  # Internship submission verification & screenshot guide
├── requirements.txt         # Pinned Scapy dependency specification
├── sample_capture.csv       # Sample synthetic capture log for review
├── sniffer.py               # Core network sniffer implementation
└── test_sniffer.py          # Unit test suite (22 tests, synthetic packets)
```

---

## 👨‍💻 Author & Acknowledgments

- **Intern**: Abhinav Chaudhary
- **Program**: CodeAlpha Cyber Security Internship
- **Task**: Basic Network Sniffer using Python & Scapy
- **Mentor / Organization**: CodeAlpha

