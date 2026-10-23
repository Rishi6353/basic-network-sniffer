#!/usr/bin/env python3
"""
==============================================================================
CodeAlpha Cyber Security Internship Task: Basic Network Sniffer
File: test_sniffer.py
Description: Comprehensive unit tests for sniffer.py.
             Tests packet decoding, payload sanitization, privacy filters,
             CSV logging, interface discovery, and synthetic packet workflows
             without requiring root/administrator privileges or live networks.
Author: Abhinav Chaudhary
==============================================================================
"""

import csv
import io
import os
import sys
import tempfile
import unittest
from unittest.mock import patch

# Defensive patch for Scapy nameserver lookup in restricted test environments
try:
    import scapy.arch
    import scapy.arch.common
    scapy.arch.read_nameservers = lambda: ["1.1.1.1", "8.8.8.8"]
    scapy.arch.common.read_nameservers = lambda: ["1.1.1.1", "8.8.8.8"]
except Exception:
    pass

from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Raw

from sniffer import (
    CSVLogger,
    NetworkSniffer,
    PacketInfo,
    build_argument_parser,
    format_packet_summary,
    generate_sample_packets,
    get_available_interfaces,
    parse_packet,
    sanitize_payload,
)


class TestPayloadSanitization(unittest.TestCase):
    """Tests for payload sanitization, binary masking, and privacy protections."""

    def test_empty_payload(self):
        """Verifies empty payloads return '<empty>'."""
        self.assertEqual(sanitize_payload(b""), "<empty>")
        self.assertEqual(sanitize_payload(None), "<empty>")  # type: ignore

    def test_printable_ascii_payload(self):
        """Verifies clean printable ASCII text is preserved."""
        raw = b"HELLO WORLD 123"
        self.assertEqual(sanitize_payload(raw), "HELLO WORLD 123")

    def test_non_printable_binary_masking(self):
        """Verifies non-printable bytes are masked with dots (like hexdump)."""
        raw = b"\x00\x01\x02HELLO\xff\xfe\x07"
        sanitized = sanitize_payload(raw)
        self.assertTrue(sanitized.startswith("...HELLO..."))

    def test_payload_truncation(self):
        """Verifies payloads longer than max_len are truncated with ellipsis."""
        long_payload = b"A" * 100
        preview = sanitize_payload(long_payload, max_len=20)
        self.assertEqual(len(preview), 23)  # 20 chars + '...'
        self.assertTrue(preview.endswith("..."))

    def test_credential_redaction_password(self):
        """Verifies password fields in payloads are safely redacted."""
        payload = b"user=alice&password=SuperSecretPassword123&action=login"
        preview = sanitize_payload(payload)
        self.assertNotIn("SuperSecretPassword123", preview)
        self.assertIn("password=[REDACTED]", preview)

    def test_credential_redaction_bearer_token(self):
        """Verifies Bearer authorization tokens are safely redacted."""
        payload = b"Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI"
        preview = sanitize_payload(payload)
        self.assertNotIn("eyJhbGciOiJIUzI1NiIsInR5cCI", preview)
        self.assertIn("[REDACTED]", preview)

    def test_credential_redaction_api_key(self):
        """Verifies API keys are safely redacted."""
        payload = b"api_key=AIzaSyA1234567890abcdef"
        preview = sanitize_payload(payload)
        self.assertNotIn("AIzaSyA1234567890abcdef", preview)
        self.assertIn("api_key=[REDACTED]", preview)


class TestPacketParsing(unittest.TestCase):
    """Tests decoding and parsing of various network packet layers."""

    def test_parse_tcp_packet(self):
        """Tests parsing IPv4 TCP packet headers and ports."""
        eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        ip = IP(src="192.168.1.50", dst="93.184.216.34")
        tcp = TCP(sport=45123, dport=80, flags="S", seq=100)
        raw = Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
        pkt = eth / ip / tcp / raw

        info = parse_packet(pkt)
        self.assertEqual(info.protocol, "TCP")
        self.assertEqual(info.src_ip, "192.168.1.50")
        self.assertEqual(info.dst_ip, "93.184.216.34")
        self.assertEqual(info.src_port, 45123)
        self.assertEqual(info.dst_port, 80)
        self.assertIn("GET / HTTP/1.1", info.payload_preview)
        self.assertGreater(info.length_bytes, 0)

    def test_parse_udp_packet(self):
        """Tests parsing IPv4 UDP packet headers and ports."""
        eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        ip = IP(src="10.0.0.5", dst="10.0.0.1")
        udp = UDP(sport=5000, dport=9000)
        raw = Raw(b"UDP_TEST_PAYLOAD")
        pkt = eth / ip / udp / raw

        info = parse_packet(pkt)
        self.assertEqual(info.protocol, "UDP")
        self.assertEqual(info.src_ip, "10.0.0.5")
        self.assertEqual(info.dst_ip, "10.0.0.1")
        self.assertEqual(info.src_port, 5000)
        self.assertEqual(info.dst_port, 9000)
        self.assertIn("UDP_TEST_PAYLOAD", info.payload_preview)

    def test_parse_dns_packet(self):
        """Tests identifying DNS packets over UDP port 53."""
        eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        ip = IP(src="192.168.1.100", dst="8.8.8.8")
        udp = UDP(sport=53000, dport=53)
        raw = Raw(b"\x12\x34\x01\x00DNS_QUERY_SIM")
        pkt = eth / ip / udp / raw

        info = parse_packet(pkt)
        self.assertEqual(info.protocol, "DNS")
        self.assertEqual(info.dst_port, 53)

    def test_parse_icmp_packet(self):
        """Tests parsing ICMP Echo Request (Ping) packets."""
        eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        ip = IP(src="192.168.1.1", dst="1.1.1.1")
        icmp = ICMP(type=8, code=0)
        pkt = eth / ip / icmp / Raw(b"PINGPING")

        info = parse_packet(pkt)
        self.assertEqual(info.protocol, "ICMP")
        self.assertEqual(info.src_ip, "192.168.1.1")
        self.assertEqual(info.dst_ip, "1.1.1.1")
        self.assertIsNone(info.src_port)
        self.assertIsNone(info.dst_port)

    def test_parse_arp_packet(self):
        """Tests parsing ARP query packets."""
        eth = Ether(src="00:11:22:33:44:55", dst="ff:ff:ff:ff:ff:ff")
        arp = ARP(op=1, psrc="192.168.1.10", pdst="192.168.1.1", hwsrc="00:11:22:33:44:55")
        pkt = eth / arp

        info = parse_packet(pkt)
        self.assertEqual(info.protocol, "ARP")
        self.assertEqual(info.src_ip, "192.168.1.10")
        self.assertEqual(info.dst_ip, "192.168.1.1")
        self.assertIsNone(info.src_port)
        self.assertIsNone(info.dst_port)

    def test_parse_ipv6_packet(self):
        """Tests parsing IPv6 packets."""
        ipv6 = IPv6(src="2001:db8::1", dst="2001:db8::2")
        tcp = TCP(sport=8080, dport=443)
        pkt = ipv6 / tcp

        info = parse_packet(pkt)
        self.assertEqual(info.protocol, "TCP")
        self.assertEqual(info.src_ip, "2001:db8::1")
        self.assertEqual(info.dst_ip, "2001:db8::2")
        self.assertEqual(info.src_port, 8080)
        self.assertEqual(info.dst_port, 443)

    def test_parse_raw_unrecognized_packet(self):
        """Verifies resilience when parsing raw bytes or minimal Ethernet frame."""
        eth = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        pkt = eth / Raw(b"UNKNOWN_PROTOCOL_PAYLOAD")

        info = parse_packet(pkt)
        self.assertEqual(info.protocol, "OTHER")
        self.assertIn("UNKNOWN_PROTOCOL_PAYLOAD", info.payload_preview)


class TestFormattingAndCSV(unittest.TestCase):
    """Tests console string formatting and CSV persistence."""

    def test_format_packet_summary(self):
        """Verifies format_packet_summary produces expected readable string."""
        info = PacketInfo(
            timestamp="2026-10-23 04:30:00.123",
            protocol="TCP",
            src_ip="192.168.1.5",
            dst_ip="10.0.0.1",
            src_port=50000,
            dst_port=443,
            length_bytes=128,
            payload_preview="TLS_DATA",
        )
        summary = format_packet_summary(info)
        self.assertIn("[2026-10-23 04:30:00.123]", summary)
        self.assertIn("TCP", summary)
        self.assertIn("192.168.1.5:50000 -> 10.0.0.1:443", summary)
        self.assertIn("128B", summary)
        self.assertIn("TLS_DATA", summary)

    def test_csv_logger_lifecycle(self):
        """Verifies CSVLogger correctly creates, writes headers, writes rows, and flushes."""
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = os.path.join(temp_dir, "test_output.csv")
            logger = CSVLogger(csv_path)

            info = PacketInfo(
                timestamp="2026-10-23 04:30:00.000",
                protocol="UDP",
                src_ip="192.168.1.10",
                dst_ip="8.8.8.8",
                src_port=5353,
                dst_port=53,
                length_bytes=84,
                payload_preview="DNS_TEST",
            )

            with logger:
                logger.log_packet(info)

            # Read back and inspect CSV contents
            self.assertTrue(os.path.exists(csv_path))
            with open(csv_path, mode="r", encoding="utf-8") as f:
                reader = list(csv.DictReader(f))
                self.assertEqual(len(reader), 1)
                row = reader[0]
                self.assertEqual(row["protocol"], "UDP")
                self.assertEqual(row["src_ip"], "192.168.1.10")
                self.assertEqual(row["dst_ip"], "8.8.8.8")
                self.assertEqual(row["src_port"], "5353")
                self.assertEqual(row["dst_port"], "53")
                self.assertEqual(row["length_bytes"], "84")
                self.assertEqual(row["payload_preview"], "DNS_TEST")


class TestSyntheticPacketGenerator(unittest.TestCase):
    """Tests synthetic packet generation for safe offline testing."""

    def test_sample_packet_generation_count(self):
        """Verifies requested packet counts are accurately generated."""
        pkts_5 = generate_sample_packets(5)
        self.assertEqual(len(pkts_5), 5)

        pkts_15 = generate_sample_packets(15)
        self.assertEqual(len(pkts_15), 15)

    def test_all_sample_packets_parseable(self):
        """Ensures all generated synthetic packets can be parsed without errors."""
        packets = generate_sample_packets(20)
        for pkt in packets:
            info = parse_packet(pkt)
            self.assertIsInstance(info, PacketInfo)
            self.assertGreater(info.length_bytes, 0)
            self.assertIn(info.protocol, ["TCP", "UDP", "ICMP", "ARP", "DNS", "OTHER", "IPv6", "IP"])


class TestNetworkSnifferEngine(unittest.TestCase):
    """Tests the NetworkSniffer orchestration engine."""

    def test_offline_simulation_mode(self):
        """Verifies end-to-end simulation mode processes packets and records stats."""
        with tempfile.TemporaryDirectory() as temp_dir:
            csv_path = os.path.join(temp_dir, "sim_test.csv")
            sniffer = NetworkSniffer(
                sample_mode=True,
                count=6,
                output_csv=csv_path,
            )

            # Suppress terminal prints during test
            with patch("sys.stdout", new=io.StringIO()):
                exit_code = sniffer.start()

            self.assertEqual(exit_code, 0)
            self.assertEqual(sniffer.packet_counter, 6)
            self.assertGreater(sniffer.total_bytes, 0)
            self.assertGreater(len(sniffer.protocol_counts), 0)

            # Verify CSV output has 6 data rows
            with open(csv_path, mode="r", encoding="utf-8") as f:
                reader = list(csv.DictReader(f))
                self.assertEqual(len(reader), 6)

    def test_available_interfaces(self):
        """Verifies get_available_interfaces returns a valid list."""
        ifaces = get_available_interfaces()
        self.assertIsInstance(ifaces, list)
        for iface in ifaces:
            self.assertIsInstance(iface, str)


class TestCLIArgumentParsing(unittest.TestCase):
    """Tests command-line argument parser configuration."""

    def setUp(self):
        self.parser = build_argument_parser()

    def test_default_arguments(self):
        """Tests CLI defaults."""
        args = self.parser.parse_args([])
        self.assertIsNone(args.interface)
        self.assertEqual(args.count, 0)
        self.assertIsNone(args.bpf_filter)
        self.assertIsNone(args.output_csv)
        self.assertFalse(args.list_interfaces)
        self.assertFalse(args.sample)

    def test_custom_arguments(self):
        """Tests parsing custom CLI options."""
        args = self.parser.parse_args([
            "-i", "en0",
            "-c", "50",
            "-f", "tcp and port 80",
            "-o", "out.csv",
            "--sample",
        ])
        self.assertEqual(args.interface, "en0")
        self.assertEqual(args.count, 50)
        self.assertEqual(args.bpf_filter, "tcp and port 80")
        self.assertEqual(args.output_csv, "out.csv")
        self.assertTrue(args.sample)


if __name__ == "__main__":
    unittest.main()

