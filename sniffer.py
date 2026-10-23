#!/usr/bin/env python3
"""
==============================================================================
CodeAlpha Cyber Security Internship Task: Basic Network Sniffer
File: sniffer.py
Description: A beginner-friendly, modular network packet sniffer using Scapy.
             Captures and decodes network traffic (IPv4, IPv6, ARP, TCP, UDP,
             ICMP, DNS), displays key header fields, provides sanitized
             payload previews, and exports capture summaries to CSV.
Author: Abhinav Chaudhary
License: MIT
==============================================================================
ETHICAL DISCLAIMER:
This tool is developed strictly for educational and authorized network
diagnostics. Unauthorized packet sniffing on networks you do not own or have
explicit written permission to monitor is illegal under cybersecurity laws
(e.g., Computer Fraud and Abuse Act, IT Act, GDPR). Never use this tool on
unauthorized networks.
==============================================================================
"""

from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import asdict, dataclass
from datetime import datetime
import os
import re
import socket
import sys
import time
from typing import Dict, List, Optional

# Defensive environment compatibility for Scapy under sandboxed or non-root environments
# Scapy's DNS layer attempts to open /etc/resolv.conf which raises PermissionError
# in restricted sandboxes or hardened environments. We patch it safely before import.
try:
    import scapy.arch
    import scapy.arch.common
    scapy.arch.read_nameservers = lambda: ["1.1.1.1", "8.8.8.8"]
    scapy.arch.common.read_nameservers = lambda: ["1.1.1.1", "8.8.8.8"]
except Exception:
    pass

try:
    from scapy.config import conf
    from scapy.error import Scapy_Exception
    from scapy.interfaces import get_if_list
    from scapy.layers.inet import ICMP, IP, TCP, UDP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import ARP, Ether
    from scapy.packet import Packet, Raw
    from scapy.sendrecv import sniff
    SCAPY_AVAILABLE = True
except ImportError as err:
    SCAPY_AVAILABLE = False
    IMPORT_ERROR_MSG = str(err)

# Try optional DNS layer import
try:
    from scapy.layers.dns import DNS
    DNS_AVAILABLE = True
except Exception:
    DNS = None  # type: ignore
    DNS_AVAILABLE = False

# Suppress Scapy verbose output and routine warnings
if SCAPY_AVAILABLE:
    conf.verb = 0


# ============================================================================
# Safe Payload Sanitization & Security Practices
# ============================================================================

# Patterns for sensitive keys that should be redacted from payload previews
# Format: (compiled_regex, replacement_template)
SENSITIVE_PATTERNS = [
    (re.compile(r"((?:password|passwd|pwd|pass)\s*[:=]\s*)([^\s;&]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"((?:api[_-]?key|secret)\s*[:=]\s*)([^\s;&]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(bearer\s+)([a-zA-Z0-9_\-\.]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"((?:authorization|set-cookie)\s*:\s*)([^\r\n]+)", re.IGNORECASE), r"\1[REDACTED]"),
]


def sanitize_payload(payload_bytes: bytes, max_len: int = 40) -> str:
    """
    Safely sanitizes a raw packet payload for preview.
    
    1. Replaces non-printable bytes with a dot (.) like standard hex dump tools.
    2. Redacts potential credentials, authentication tokens, and passwords to
       strictly follow cybersecurity privacy and safety standards.
    3. Truncates length to avoid terminal overflow.
    
    Args:
        payload_bytes: Raw bytes from the packet.
        max_len: Maximum length of the returned preview string.
        
    Returns:
        A sanitized, printable string preview.
    """
    if not payload_bytes:
        return "<empty>"

    # Convert bytes to printable ASCII, replacing non-printable bytes with '.'
    printable_chars: List[str] = []
    for byte in payload_bytes:
        if 32 <= byte <= 126:
            printable_chars.append(chr(byte))
        else:
            printable_chars.append(".")
    preview = "".join(printable_chars)

    # Redact sensitive credentials if detected
    for pattern, replacement in SENSITIVE_PATTERNS:
        preview = pattern.sub(replacement, preview)

    # Truncate to maximum specified length
    if len(preview) > max_len:
        preview = preview[:max_len] + "..."

    return preview


# ============================================================================
# Packet Data Model & Parser
# ============================================================================

@dataclass
class PacketInfo:
    """Structured representation of decoded packet metadata."""
    timestamp: str
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: Optional[int]
    dst_port: Optional[int]
    length_bytes: int
    payload_preview: str

    def to_dict(self) -> Dict[str, str]:
        """Convert packet data to a dictionary suitable for CSV serialization."""
        return {
            "timestamp": self.timestamp,
            "protocol": self.protocol,
            "src_ip": self.src_ip,
            "src_port": str(self.src_port) if self.src_port is not None else "N/A",
            "dst_ip": self.dst_ip,
            "dst_port": str(self.dst_port) if self.dst_port is not None else "N/A",
            "length_bytes": str(self.length_bytes),
            "payload_preview": self.payload_preview,
        }


def parse_packet(packet: Packet) -> PacketInfo:
    """
    Parses a Scapy network packet and extracts key header fields.
    
    Handles IPv4, IPv6, ARP, TCP, UDP, ICMP, DNS, and raw payloads.
    Provides robust fallback handling for malformed or unknown packet formats.
    
    Args:
        packet: Scapy Packet object.
        
    Returns:
        PacketInfo containing decoded metadata.
    """
    # Timestamp formatted with microsecond precision
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    length = len(packet)

    protocol = "OTHER"
    src_ip = "N/A"
    dst_ip = "N/A"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # Layer 2 / Layer 3 extraction
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = "IP"
    elif packet.haslayer(IPv6):
        ipv6_layer = packet[IPv6]
        src_ip = ipv6_layer.src
        dst_ip = ipv6_layer.dst
        protocol = "IPv6"
    elif packet.haslayer(ARP):
        arp_layer = packet[ARP]
        src_ip = arp_layer.psrc or "0.0.0.0"
        dst_ip = arp_layer.pdst or "0.0.0.0"
        protocol = "ARP"

    # Layer 4 / Transport Layer extraction
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        protocol = "TCP"
        src_port = tcp_layer.sport
        dst_port = tcp_layer.dport
    elif packet.haslayer(UDP):
        udp_layer = packet[UDP]
        protocol = "UDP"
        src_port = udp_layer.sport
        dst_port = udp_layer.dport
        # Check for DNS
        if DNS_AVAILABLE and packet.haslayer(DNS):
            protocol = "DNS"
        elif src_port == 53 or dst_port == 53:
            protocol = "DNS"
    elif packet.haslayer(ICMP):
        protocol = "ICMP"

    # Payload extraction and safe sanitization
    raw_payload = b""
    if packet.haslayer(Raw):
        raw_payload = bytes(packet[Raw].load)
    elif hasattr(packet, "payload") and packet.payload:
        try:
            raw_payload = bytes(packet.payload.payload)
        except Exception:
            raw_payload = b""

    payload_text = sanitize_payload(raw_payload)

    return PacketInfo(
        timestamp=now,
        protocol=protocol,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        length_bytes=length,
        payload_preview=payload_text,
    )


def format_packet_summary(info: PacketInfo) -> str:
    """
    Formats PacketInfo into a clean, human-readable terminal line.
    
    Example:
        [2026-10-23 04:45:12.123] TCP   | 192.168.1.15:52341 -> 142.250.190.46:443 | Len: 64B | Payload: GET /index.html...
    """
    src_str = f"{info.src_ip}:{info.src_port}" if info.src_port is not None else info.src_ip
    dst_str = f"{info.dst_ip}:{info.dst_port}" if info.dst_port is not None else info.dst_ip
    flow = f"{src_str} -> {dst_str}"

    return (
        f"[{info.timestamp}] {info.protocol:<5} | "
        f"{flow:<44} | "
        f"Len: {info.length_bytes:>5}B | "
        f"Preview: {info.payload_preview}"
    )


# ============================================================================
# CSV Output Logging
# ============================================================================

class CSVLogger:
    """Manages streaming writes of captured packet metadata to a CSV file."""

    CSV_HEADERS = [
        "timestamp",
        "protocol",
        "src_ip",
        "src_port",
        "dst_ip",
        "dst_port",
        "length_bytes",
        "payload_preview",
    ]

    def __init__(self, filepath: str):
        self.filepath = filepath
        self._file = None
        self._writer = None

    def open(self) -> None:
        """Opens the CSV file and writes the header row."""
        try:
            # Check if directory exists, if not create it
            dirname = os.path.dirname(self.filepath)
            if dirname and not os.path.exists(dirname):
                os.makedirs(dirname, exist_ok=True)

            self._file = open(self.filepath, mode="w", newline="", encoding="utf-8")
            self._writer = csv.DictWriter(self._file, fieldnames=self.CSV_HEADERS)
            self._writer.writeheader()
            self._file.flush()
        except OSError as e:
            raise OSError(f"Could not open CSV file '{self.filepath}': {e}") from e

    def log_packet(self, packet_info: PacketInfo) -> None:
        """Writes a single packet record to the CSV and flushes immediately."""
        if self._writer and self._file:
            self._writer.writerow(packet_info.to_dict())
            self._file.flush()

    def close(self) -> None:
        """Safely closes the CSV file."""
        if self._file and not self._file.closed:
            self._file.close()
            self._file = None
            self._writer = None

    def __enter__(self) -> CSVLogger:
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()


# ============================================================================
# Interface Utilities
# ============================================================================

def get_available_interfaces() -> List[str]:
    """
    Returns a list of network interface names available on the host system.
    Tries Scapy's interface discovery, falling back to socket.if_nameindex().
    """
    interfaces: List[str] = []
    try:
        scapy_ifs = get_if_list()
        if scapy_ifs:
            interfaces.extend(scapy_ifs)
    except Exception:
        pass

    # Fallback to standard Python socket interface discovery (supported on macOS/Linux)
    if not interfaces and hasattr(socket, "if_nameindex"):
        try:
            interfaces = [name for _, name in socket.if_nameindex()]
        except Exception:
            pass

    # Dedup and sort
    return sorted(list(set(interfaces)))


# ============================================================================
# Synthetic Packet Generator (Safe Demonstration & Testing)
# ============================================================================

def generate_sample_packets(count: int = 10) -> List[Packet]:
    """
    Generates realistic synthetic network packets in memory using Scapy.
    
    This provides an offline, safe demonstration mode that does NOT require:
    - Root or administrator privileges
    - Live network access
    - Promiscuous hardware capture
    
    Useful for unit testing, CI pipelines, and academic grading demonstrations.
    
    Args:
        count: Number of synthetic packets to generate.
        
    Returns:
        List of Scapy Packet instances.
    """
    eth_header = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")

    synthetic_pool = [
        # 1. HTTP GET Request
        eth_header.copy() / IP(src="192.168.1.105", dst="93.184.216.34") /
        TCP(sport=51234, dport=80, flags="PA", seq=1000, ack=2000) /
        Raw(b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n"),

        # 2. HTTPS TLS Handshake Client Hello attempt
        eth_header.copy() / IP(src="192.168.1.105", dst="142.250.190.46") /
        TCP(sport=51235, dport=443, flags="S", seq=100) /
        Raw(b"\x16\x03\x01\x00\xa5\x01\x00\x00\xa1\x03\x03TLS_SIMULATION_PACKET_DATA"),

        # 3. DNS Standard Query (A record for codealpha.tech)
        eth_header.copy() / IP(src="192.168.1.105", dst="8.8.8.8") /
        UDP(sport=53001, dport=53) /
        Raw(b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09codealpha\x04tech\x00\x00\x01\x00\x01"),

        # 4. ICMP Echo Request (Ping)
        eth_header.copy() / IP(src="192.168.1.105", dst="1.1.1.1") /
        ICMP(type=8, code=0, id=0x1234, seq=1) /
        Raw(b"abcdefghijklmnopqrstuvwabcdefghi"),

        # 5. ARP Request (Who has 192.168.1.1? Tell 192.168.1.105)
        Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff") /
        ARP(op=1, psrc="192.168.1.105", pdst="192.168.1.1", hwsrc="00:11:22:33:44:55"),

        # 6. NTP Time Query (UDP port 123)
        eth_header.copy() / IP(src="192.168.1.105", dst="216.239.35.0") /
        UDP(sport=48212, dport=123) /
        Raw(b"\x23\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00NTP_REQUEST_TIMESTAMP_DATA"),

        # 7. IPv6 TCP Packet
        IPv6(src="2001:db8::1", dst="2001:db8::2") /
        TCP(sport=60001, dport=8080, flags="S") /
        Raw(b"IPV6_PAYLOAD_TEST"),

        # 8. Safe credential redaction verification packet
        eth_header.copy() / IP(src="192.168.1.105", dst="192.168.1.200") /
        TCP(sport=49999, dport=8000) /
        Raw(b"user=admin&password=SuperSecretPassword123&action=login"),
    ]

    # Repeat or slice to match requested count
    packets: List[Packet] = []
    while len(packets) < count:
        for p in synthetic_pool:
            packets.append(p)
            if len(packets) >= count:
                break
    return packets


# ============================================================================
# Main Sniffer Engine
# ============================================================================

class NetworkSniffer:
    """Coordinates packet capture, formatting, CSV logging, and statistics."""

    def __init__(
        self,
        interface: Optional[str] = None,
        count: int = 0,
        bpf_filter: Optional[str] = None,
        output_csv: Optional[str] = None,
        sample_mode: bool = False,
    ):
        self.interface = interface
        self.count = count
        self.bpf_filter = bpf_filter
        self.output_csv = output_csv
        self.sample_mode = sample_mode

        self.packet_counter = 0
        self.total_bytes = 0
        self.protocol_counts: Counter[str] = Counter()
        self.csv_logger: Optional[CSVLogger] = None
        self.start_time: Optional[datetime] = None

    def process_packet(self, packet: Packet) -> None:
        """Callback invoked for each captured packet."""
        try:
            info = parse_packet(packet)
            self.packet_counter += 1
            self.total_bytes += info.length_bytes
            self.protocol_counts[info.protocol] += 1

            # Print formatted summary to terminal
            print(format_packet_summary(info))

            # Write to CSV if enabled
            if self.csv_logger:
                self.csv_logger.log_packet(info)

        except Exception as err:
            print(f"[!] Error processing packet: {err}", file=sys.stderr)

    def print_banner(self) -> None:
        """Displays project title, settings, and ethical warning."""
        print("=" * 80)
        print("  CodeAlpha Cyber Security Internship: Basic Network Sniffer")
        print("=" * 80)
        print("  ETHICAL USAGE WARNING:")
        print("  Capturing network traffic without explicit authorization is illegal.")
        print("  Ensure you have permission to monitor traffic on this network.")
        print("-" * 80)
        mode_str = "OFFLINE SYNTHETIC SAMPLE MODE" if self.sample_mode else "LIVE NETWORK CAPTURE"
        print(f"  Mode:            {mode_str}")
        print(f"  Interface:       {self.interface or 'Default System Interface'}")
        print(f"  Filter (BPF):    {self.bpf_filter or 'None (all traffic)'}")
        print(f"  Packet Count:    {'Unlimited (press Ctrl+C to stop)' if self.count == 0 else self.count}")
        print(f"  CSV Output:      {self.output_csv or 'Disabled'}")
        print("=" * 80)
        print("Sniffing started... Press Ctrl+C at any time to stop.\n")

    def print_summary(self) -> None:
        """Displays summary statistics after capture completes."""
        elapsed_sec = 0.0
        if self.start_time:
            elapsed_sec = (datetime.now() - self.start_time).total_seconds()

        print("\n" + "=" * 80)
        print("  Capture Statistics Summary")
        print("=" * 80)
        print(f"  Total Packets Captured: {self.packet_counter}")
        print(f"  Total Data Processed:   {self.total_bytes:,} bytes")
        print(f"  Elapsed Time:           {elapsed_sec:.2f} seconds")
        print("\n  Protocol Breakdown:")
        if self.protocol_counts:
            for proto, count in self.protocol_counts.most_common():
                pct = (count / self.packet_counter) * 100 if self.packet_counter else 0
                print(f"    - {proto:<8}: {count:>5} packets ({pct:>5.1f}%)")
        else:
            print("    (No packets captured)")

        if self.output_csv:
            print(f"\n  [+] Capture data saved to CSV: {os.path.abspath(self.output_csv)}")
        print("=" * 80)

    def start(self) -> int:
        """
        Executes the network sniffer.
        
        Returns:
            Exit code (0 for success, non-zero for error).
        """
        self.start_time = datetime.now()
        self.print_banner()

        # Initialize CSV logger if configured
        if self.output_csv:
            try:
                self.csv_logger = CSVLogger(self.output_csv)
                self.csv_logger.open()
            except OSError as err:
                print(f"[!] Error initializing CSV logger: {err}", file=sys.stderr)
                return 1

        try:
            if self.sample_mode:
                # Safe synthetic packet simulation
                target_count = self.count if self.count > 0 else 10
                print(f"[*] Simulating capture of {target_count} synthetic test packets...\n")
                sample_packets = generate_sample_packets(target_count)
                for pkt in sample_packets:
                    self.process_packet(pkt)
                    time.sleep(0.05)  # slight delay for realistic visualization
            else:
                # Live network packet capture via Scapy
                sniff_kwargs = {
                    "prn": self.process_packet,
                    "store": False,
                }
                if self.interface:
                    sniff_kwargs["iface"] = self.interface
                if self.count > 0:
                    sniff_kwargs["count"] = self.count
                if self.bpf_filter:
                    sniff_kwargs["filter"] = self.bpf_filter

                sniff(**sniff_kwargs)

        except KeyboardInterrupt:
            print("\n[*] Capture interrupted by user (Ctrl+C). Stopping gracefully...")
        except Scapy_Exception as scapy_err:
            err_msg = str(scapy_err)
            print(f"\n[!] Scapy Capture Error: {err_msg}", file=sys.stderr)
            if "bpf" in err_msg.lower() or "permission" in err_msg.lower() or "not permitted" in err_msg.lower():
                print("\n" + "-" * 80, file=sys.stderr)
                print("  PERMISSION / PRIVILEGE NOTICE:", file=sys.stderr)
                print("  Live network packet capture requires root or administrative privileges.", file=sys.stderr)
                print("  On macOS and Linux, raw packet capture requires root or /dev/bpf access.", file=sys.stderr)
                print("\n  Recommended Solutions:", file=sys.stderr)
                print(f"    1. Run with sudo: sudo ./.venv/bin/python sniffer.py {' '.join(sys.argv[1:])}", file=sys.stderr)
                print("    2. Or run offline safe simulation (no sudo needed):", file=sys.stderr)
                print(f"       python sniffer.py --sample -c 10 -o sample_capture.csv", file=sys.stderr)
                print("-" * 80 + "\n", file=sys.stderr)
            return 2
        except PermissionError as perm_err:
            print(f"\n[!] Permission Error: {perm_err}", file=sys.stderr)
            print("    Please run this script with administrative privileges (sudo) for live capture,", file=sys.stderr)
            print("    or use '--sample' to run offline synthetic packet demonstrations without root.", file=sys.stderr)
            return 2
        except Exception as unexpected_err:
            print(f"\n[!] Unexpected Error during packet sniffing: {unexpected_err}", file=sys.stderr)
            return 3
        finally:
            if self.csv_logger:
                self.csv_logger.close()
            self.print_summary()

        return 0


# ============================================================================
# CLI Setup and Entry Point
# ============================================================================

def build_argument_parser() -> argparse.ArgumentParser:
    """Builds and returns the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="sniffer.py",
        description="A lightweight, educational network packet sniffer using Python and Scapy.",
        epilog=(
            "Examples:\n"
            "  # Safe offline demonstration (no sudo needed):\n"
            "  python sniffer.py --sample -c 10 -o sample_capture.csv\n\n"
            "  # List network interfaces:\n"
            "  python sniffer.py --list-interfaces\n\n"
            "  # Live capture 20 packets on interface en0 (requires sudo on macOS/Linux):\n"
            "  sudo python sniffer.py -i en0 -c 20\n\n"
            "  # Live capture TCP port 80/443 traffic and export to CSV:\n"
            "  sudo python sniffer.py -i en0 -f 'tcp port 80 or tcp port 443' -o web_traffic.csv\n"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-i", "--interface",
        type=str,
        default=None,
        help="Network interface to sniff on (e.g., en0, lo0, eth0). Omit for default.",
    )
    parser.add_argument(
        "-c", "--count",
        type=int,
        default=0,
        help="Number of packets to capture (default: 0 = capture continuously until Ctrl+C).",
    )
    parser.add_argument(
        "-f", "--filter",
        dest="bpf_filter",
        type=str,
        default=None,
        help="Berkeley Packet Filter (BPF) syntax string (e.g., 'tcp', 'udp port 53', 'icmp').",
    )
    parser.add_argument(
        "-o", "--output",
        dest="output_csv",
        type=str,
        default=None,
        help="Path to output CSV file for exporting packet log.",
    )
    parser.add_argument(
        "-l", "--list-interfaces",
        action="store_true",
        help="Display all detected network interfaces on the system and exit.",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="Run in safe offline simulation mode using synthetic packets (no root or network required).",
    )
    return parser


def main() -> int:
    """Entry point for the network sniffer CLI."""
    if not SCAPY_AVAILABLE:
        print("[!] ERROR: Scapy is not installed or failed to import.", file=sys.stderr)
        print(f"    Import details: {IMPORT_ERROR_MSG}", file=sys.stderr)
        print("    Please install dependencies in your virtual environment:", file=sys.stderr)
        print("      pip install -r requirements.txt", file=sys.stderr)
        return 1

    parser = build_argument_parser()
    args = parser.parse_args()

    # Handle interface listing request
    if args.list_interfaces:
        interfaces = get_available_interfaces()
        print("\nAvailable Network Interfaces:")
        print("-" * 40)
        if interfaces:
            for idx, iface in enumerate(interfaces, start=1):
                print(f"  {idx:>2}. {iface}")
        else:
            print("  [!] No interfaces detected or permissions restricted.")
        print("-" * 40)
        print("Tip: Use '-i <interface_name>' to specify the capture interface.\n")
        return 0

    # Validate packet count
    if args.count < 0:
        print("[!] Error: Packet count (-c / --count) cannot be negative.", file=sys.stderr)
        return 1

    # Validate interface if provided
    if args.interface and not args.sample:
        available = get_available_interfaces()
        if available and args.interface not in available:
            print(f"[!] Warning: Interface '{args.interface}' was not found in detected interfaces:", file=sys.stderr)
            print(f"    Available interfaces: {', '.join(available)}", file=sys.stderr)
            print("    Attempting to proceed anyway (interface may be virtual or restricted)...\n")

    # Instantiate and start the sniffer
    sniffer = NetworkSniffer(
        interface=args.interface,
        count=args.count,
        bpf_filter=args.bpf_filter,
        output_csv=args.output_csv,
        sample_mode=args.sample,
    )
    return sniffer.start()


if __name__ == "__main__":
    sys.exit(main())
