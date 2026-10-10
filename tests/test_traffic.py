import unittest
from tempfile import TemporaryDirectory
from pathlib import Path

from scapy.layers.inet import IP, TCP, UDP
from scapy.packet import Raw
from scapy.utils import PcapNgWriter, wrpcap

from sentinelshield.collection.synthetic import (
    make_synthetic_scenario,
    make_synthetic_stream,
)
from sentinelshield.processing.traffic import (
    PacketRecord,
    aggregate_windows,
    read_pcap,
    record_from_packet,
)


class PacketRecordTests(unittest.TestCase):
    def test_extracts_header_metadata_without_payload(self):
        packet = IP(src="192.0.2.1", dst="198.51.100.2") / TCP(
            sport=12345, dport=443, flags="S"
        ) / Raw(load=b"private payload")
        packet.time = 12.5

        record = record_from_packet(packet)

        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.source_ip, "192.0.2.1")
        self.assertEqual(record.protocol, "tcp")
        self.assertEqual(record.destination_port, 443)
        self.assertEqual(record.tcp_flags, 0x02)
        self.assertFalse(hasattr(record, "payload"))

    def test_ignores_non_ip_packet(self):
        self.assertIsNone(record_from_packet(Raw(load=b"not an IP packet")))

    def test_extracts_udp(self):
        record = record_from_packet(
            IP(src="192.0.2.1", dst="198.51.100.2") / UDP(sport=12, dport=53)
        )
        self.assertIsNotNone(record)
        assert record is not None
        self.assertEqual(record.protocol, "udp")
        self.assertEqual(record.destination_port, 53)

    def test_reads_packet_metadata_from_pcap(self):
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            capture_path = Path(directory) / "sample.pcap"
            wrpcap(
                str(capture_path),
                [IP(src="192.0.2.1", dst="198.51.100.2") / TCP(dport=443)],
            )
            records = list(read_pcap(capture_path))

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].source_kind, "pcap")
        self.assertEqual(records[0].protocol, "tcp")

    def test_reads_packet_metadata_from_pcapng(self):
        with TemporaryDirectory(dir=Path.cwd()) as directory:
            capture_path = Path(directory) / "sample.pcapng"
            with PcapNgWriter(str(capture_path)) as writer:
                writer.write(IP(src="192.0.2.1", dst="198.51.100.2") / UDP(dport=53))
            records = list(read_pcap(capture_path))

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].protocol, "udp")


class WindowAggregationTests(unittest.TestCase):
    def test_aggregates_protocol_volume_flags_and_flows(self):
        packets = [
            PacketRecord(1.0, "192.0.2.1", "198.51.100.2", "tcp", 60, 1000, 443, 0x02),
            PacketRecord(2.0, "192.0.2.1", "198.51.100.2", "tcp", 80, 1000, 443, 0x12),
            PacketRecord(5.0, "192.0.2.2", "198.51.100.3", "udp", 40, 2000, 53),
        ]

        windows = aggregate_windows(packets, window_seconds=5)

        self.assertEqual(len(windows), 2)
        first = windows[0]
        self.assertEqual(first.packet_count, 2)
        self.assertEqual(first.total_bytes, 140)
        self.assertEqual(first.tcp_packets, 2)
        self.assertEqual(first.syn_count, 1)
        self.assertEqual(first.syn_ack_count, 1)
        self.assertEqual(first.ack_count, 1)
        self.assertEqual(first.syn_ratio, 0.5)
        self.assertEqual(first.unique_flows, 1)
        self.assertEqual(windows[1].udp_packets, 1)

    def test_zero_tcp_packets_has_zero_syn_ratio(self):
        packet = PacketRecord(1.0, "192.0.2.1", "198.51.100.2", "udp", 40)
        self.assertEqual(aggregate_windows([packet])[0].syn_ratio, 0.0)

    def test_rejects_non_positive_window(self):
        with self.assertRaises(ValueError):
            aggregate_windows([], window_seconds=0)

    def test_synthetic_traffic_is_explicitly_labeled(self):
        packets = make_synthetic_scenario("syn_heavy")
        self.assertTrue(all(packet.source_kind == "synthetic" for packet in packets))
        self.assertTrue(all(packet.scenario_label == "syn_heavy" for packet in packets))
        features = aggregate_windows(packets)[0]
        self.assertEqual(features.syn_ratio, 1.0)
        self.assertEqual(features.source_kind, "synthetic")

    def test_rejects_unknown_scenario(self):
        with self.assertRaises(ValueError):
            make_synthetic_scenario("real_attack")

    def test_dashboard_stream_has_deterministic_controlled_phases(self):
        first = make_synthetic_stream()
        second = make_synthetic_stream()
        self.assertEqual(first, second)
        windows = aggregate_windows(first)
        self.assertEqual(len(windows), 30)
        self.assertTrue(all(window.source_kind == "synthetic" for window in windows))
        self.assertLess(windows[0].packets_per_second, 100)
        self.assertGreater(windows[8].packets_per_second, 100)
        self.assertLess(windows[14].packets_per_second, 100)
        self.assertGreater(windows[14].syn_ratio, 0.7)
        self.assertGreater(windows[20].packets_per_second, 100)
        self.assertGreater(windows[20].syn_ratio, 0.7)


if __name__ == "__main__":
    unittest.main()
