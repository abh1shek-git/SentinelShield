"""Tests for bounded, metadata-only live capture."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from scapy.layers.inet import IP, TCP

from sentinelshield.collection.live import (
    MAX_CAPTURE_SECONDS,
    capture_live_metadata,
    list_capture_interfaces,
)


class LiveCaptureTests(unittest.TestCase):
    def test_capture_is_bounded_and_does_not_store_packet_objects(self):
        timestamp = 100.0
        packet = IP(src="192.0.2.10", dst="198.51.100.20") / TCP(
            sport=50000, dport=443, flags="S"
        )
        packet.time = timestamp

        def fake_sniff(*, iface, timeout, prn, store):
            self.assertEqual(iface, "test0")
            self.assertEqual(timeout, 10)
            self.assertFalse(store)
            prn(packet)
            return [packet]

        with patch("sentinelshield.collection.live.sniff", side_effect=fake_sniff):
            records, source_kind = capture_live_metadata("test0", 10)

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].source_ip, "192.0.2.10")
        self.assertEqual(records[0].tcp_flags, 0x02)
        self.assertEqual(records[0].source_kind, source_kind)
        self.assertTrue(source_kind.startswith("live:"))
        self.assertFalse(hasattr(records[0], "payload"))

    def test_rejects_invalid_interface_and_duration(self):
        with self.assertRaises(ValueError):
            capture_live_metadata("", 10)
        with self.assertRaises(ValueError):
            capture_live_metadata("test0", MAX_CAPTURE_SECONDS + 1)

    def test_lists_unique_sorted_interfaces(self):
        with patch(
            "sentinelshield.collection.live.get_if_list",
            return_value=["zeta", "alpha", "alpha"],
        ):
            self.assertEqual(list_capture_interfaces(), ["alpha", "zeta"])


if __name__ == "__main__":
    unittest.main()
