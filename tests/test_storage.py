import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from sentinelshield.detection.rules import DetectionResult
from sentinelshield.processing.traffic import PacketRecord, aggregate_windows
from sentinelshield.storage import SQLiteStore


class SQLiteStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = TemporaryDirectory(dir=Path.cwd())
        self.addCleanup(self.temp_directory.cleanup)
        self.database_path = Path(self.temp_directory.name) / "sentinelshield.sqlite3"
        self.store = SQLiteStore(self.database_path)
        self.features = aggregate_windows(
            [
                PacketRecord(
                    timestamp=100.0,
                    source_ip="192.0.2.10",
                    destination_ip="198.51.100.20",
                    protocol="tcp",
                    packet_bytes=60,
                    source_port=42000,
                    destination_port=443,
                    tcp_flags=0x02,
                    source_kind="synthetic",
                )
            ]
        )[0]

    def alert(self, label="Unusual Traffic"):
        return DetectionResult(
            label=label,
            reasons=("test reason",),
            observed_pps=0.2,
            syn_ratio=1.0,
            syn_pps=0.2,
            adaptive_threshold_pps=0.1,
            baseline_samples=3,
            baseline_ready=True,
        )

    def test_window_storage_is_idempotent_and_persists_across_instances(self):
        self.assertTrue(self.store.record_window(self.features))
        self.assertFalse(self.store.record_window(self.features))

        reloaded_store = SQLiteStore(self.database_path)
        rows = reloaded_store.list_traffic_windows()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["source_kind"], "synthetic")
        self.assertEqual(rows[0]["features"]["packet_count"], 1)

    def test_alerts_are_deduplicated_and_normal_results_are_not_saved(self):
        result = self.alert()
        self.assertTrue(self.store.record_detection(self.features, result))
        self.assertFalse(self.store.record_detection(self.features, result))
        self.assertFalse(self.store.record_detection(self.features, self.alert("Normal")))

        alerts = self.store.list_detection_events()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["label"], "Unusual Traffic")
        self.assertEqual(alerts[0]["reasons"], ["test reason"])

    def test_simulated_block_expires_without_deleting_history(self):
        created = datetime(2026, 1, 1, tzinfo=timezone.utc)
        block_id = self.store.record_simulated_block(
            "192.0.2.7",
            reason="controlled test entry",
            ttl_seconds=30,
            created_at=created,
        )
        before_expiry = self.store.active_simulated_blocks(
            as_of=created + timedelta(seconds=29)
        )
        at_expiry = self.store.active_simulated_blocks(
            as_of=created + timedelta(seconds=30)
        )

        self.assertEqual(before_expiry[0]["id"], block_id)
        self.assertEqual(before_expiry[0]["mode"], "simulation")
        self.assertEqual(at_expiry, [])
        self.assertEqual(len(self.store.list_mitigation_events()), 1)

    def test_rejects_invalid_ip_empty_reason_and_non_positive_ttl(self):
        with self.assertRaisesRegex(ValueError, "valid IPv4 or IPv6"):
            self.store.record_simulated_block("not-an-ip", reason="test")
        with self.assertRaisesRegex(ValueError, "ttl_seconds"):
            self.store.record_simulated_block("192.0.2.7", reason="test", ttl_seconds=0)
        with self.assertRaisesRegex(ValueError, "ttl_seconds"):
            self.store.record_simulated_block(
                "192.0.2.7", reason="test", ttl_seconds=float("nan")
            )
        with self.assertRaisesRegex(ValueError, "reason"):
            self.store.record_simulated_block("192.0.2.7", reason="  ")
        self.assertEqual(self.store.list_mitigation_events(), [])

    def test_rejects_naive_expiration_clock(self):
        with self.assertRaisesRegex(ValueError, "timezone-aware"):
            self.store.active_simulated_blocks(as_of=datetime(2026, 1, 1))


if __name__ == "__main__":
    unittest.main()
