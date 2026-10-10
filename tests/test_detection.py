import unittest

from sentinelshield.collection.synthetic import make_synthetic_scenario
from sentinelshield.detection import DetectionConfig, RuleBasedDetector
from sentinelshield.processing.traffic import PacketRecord, aggregate_windows


def window_with_rates(packet_count: int, *, window_seconds: float = 1.0):
    records = [
        PacketRecord(
            timestamp=10.0 + index * (window_seconds / max(packet_count, 1)),
            source_ip="192.0.2.10",
            destination_ip="198.51.100.20",
            protocol="udp",
            packet_bytes=100,
            source_port=40000,
            destination_port=53,
        )
        for index in range(packet_count)
    ]
    return aggregate_windows(records, window_seconds=window_seconds)[0]


class RuleBasedDetectorTests(unittest.TestCase):
    def setUp(self):
        self.config = DetectionConfig(
            minimum_unusual_pps=5,
            minimum_baseline_samples=3,
            baseline_window_count=6,
            minimum_syn_pps=1,
        )

    def test_cold_start_uses_documented_absolute_floor(self):
        detector = RuleBasedDetector(self.config)
        result = detector.evaluate(window_with_rates(5))
        self.assertEqual(result.label, "Normal")
        self.assertFalse(result.baseline_ready)
        self.assertEqual(result.adaptive_threshold_pps, 5)

    def test_normal_windows_build_robust_adaptive_baseline(self):
        detector = RuleBasedDetector(self.config)
        for _ in range(3):
            self.assertEqual(detector.evaluate(window_with_rates(4)).label, "Normal")

        result = detector.evaluate(window_with_rates(10))
        self.assertTrue(result.baseline_ready)
        self.assertEqual(result.adaptive_threshold_pps, 7)
        self.assertEqual(result.label, "Unusual Traffic")

    def test_high_volume_alone_is_not_labeled_ddos(self):
        detector = RuleBasedDetector(self.config)
        result = detector.evaluate(window_with_rates(10))
        self.assertEqual(result.label, "Unusual Traffic")
        self.assertTrue(any("Packet rate" in reason for reason in result.reasons))

    def test_syn_pattern_alone_is_a_cautious_label(self):
        config = DetectionConfig(
            minimum_unusual_pps=100,
            minimum_baseline_samples=3,
            baseline_window_count=6,
            suspicious_syn_ratio=0.7,
            minimum_syn_pps=1,
        )
        detector = RuleBasedDetector(config)
        result = detector.evaluate(
            aggregate_windows(make_synthetic_scenario("syn_heavy"))[0]
        )
        self.assertEqual(result.label, "Suspicious TCP SYN Pattern")

    def test_combined_high_rate_and_syn_pattern_is_potential_only(self):
        detector = RuleBasedDetector(self.config)
        packets = [
            PacketRecord(
                timestamp=10.0 + index * 0.01,
                source_ip="192.0.2.10",
                destination_ip="198.51.100.20",
                protocol="tcp",
                packet_bytes=60,
                source_port=40000 + index,
                destination_port=443,
                tcp_flags=0x02,
            )
            for index in range(30)
        ]
        result = detector.evaluate(aggregate_windows(packets)[0])
        self.assertEqual(result.label, "Potential DDoS Activity")
        self.assertEqual(len(result.reasons), 2)

    def test_suspicious_windows_do_not_poison_baseline(self):
        detector = RuleBasedDetector(self.config)
        detector.evaluate(window_with_rates(4))
        detector.evaluate(window_with_rates(4))
        detector.evaluate(window_with_rates(10))
        self.assertEqual(detector.baseline_samples, (4.0, 4.0))

    def test_config_rejects_invalid_parameters(self):
        with self.assertRaises(ValueError):
            DetectionConfig(suspicious_syn_ratio=1.5)
        with self.assertRaises(ValueError):
            DetectionConfig(minimum_baseline_samples=5, baseline_window_count=4)


if __name__ == "__main__":
    unittest.main()
