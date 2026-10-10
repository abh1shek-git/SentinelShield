"""Explicitly synthetic labeled windows for reproducible pipeline demos."""

from __future__ import annotations

import numpy as np
import pandas as pd

from sentinelshield.evaluation.model import FEATURE_COLUMNS


LABELS = (
    "Normal",
    "Unusual Traffic",
    "Suspicious TCP SYN Pattern",
    "Potential DDoS Activity",
)


def generate_synthetic_dataset(
    samples_per_class: int = 80, random_state: int = 42
) -> pd.DataFrame:
    """Build deterministic, clearly marked feature rows for software demos.

    The ranges encode simple scenarios to verify the training and inference
    pipeline. They are not network measurements and are unsuitable for claims
    about real-world detection quality.
    """
    if samples_per_class < 5:
        raise ValueError("samples_per_class must be at least five for a holdout split")

    rng = np.random.default_rng(random_state)
    rows: list[dict[str, float | int | str]] = []
    for label in LABELS:
        for _ in range(samples_per_class):
            if label == "Normal":
                pps = int(rng.integers(4, 21))
                tcp_share = float(rng.uniform(0.25, 0.70))
                syn_share = float(rng.uniform(0.02, 0.30))
            elif label == "Unusual Traffic":
                pps = int(rng.integers(80, 251))
                tcp_share = float(rng.uniform(0.15, 0.75))
                syn_share = float(rng.uniform(0.05, 0.55))
            elif label == "Suspicious TCP SYN Pattern":
                pps = int(rng.integers(20, 101))
                tcp_share = float(rng.uniform(0.70, 0.98))
                syn_share = float(rng.uniform(0.75, 0.99))
            else:
                pps = int(rng.integers(251, 601))
                tcp_share = float(rng.uniform(0.70, 0.98))
                syn_share = float(rng.uniform(0.80, 0.995))

            packet_count = pps * 5
            tcp_count = int(packet_count * tcp_share)
            udp_count = packet_count - tcp_count
            syn_count = int(tcp_count * syn_share)
            syn_ack_count = int(tcp_count * rng.uniform(0.01, 0.12))
            average_size = int(rng.integers(60, 121))
            total_bytes = packet_count * average_size
            icmp_count = int(rng.integers(0, max(1, packet_count // 100 + 1)))
            rows.append(
                {
                    "packet_count": packet_count,
                    "total_bytes": total_bytes,
                    "packets_per_second": float(pps),
                    "bytes_per_second": total_bytes / 5.0,
                    "average_packet_bytes": float(average_size),
                    "minimum_packet_bytes": int(max(40, average_size - rng.integers(0, 20))),
                    "maximum_packet_bytes": int(average_size + rng.integers(0, 50)),
                    "tcp_packets": tcp_count,
                    "udp_packets": udp_count,
                    "icmp_packets": icmp_count,
                    "other_packets": 0,
                    "syn_count": syn_count,
                    "syn_ack_count": syn_ack_count,
                    "ack_count": int(tcp_count * rng.uniform(0.1, 0.8)),
                    "fin_count": int(tcp_count * rng.uniform(0.01, 0.2)),
                    "rst_count": int(tcp_count * rng.uniform(0.01, 0.15)),
                    "syn_ratio": syn_count / tcp_count if tcp_count else 0.0,
                    "unique_sources": int(rng.integers(1, 20)),
                    "unique_destinations": int(rng.integers(1, 8)),
                    "unique_destination_ports": int(rng.integers(1, 40)),
                    "unique_flows": int(rng.integers(1, min(packet_count, 100) + 1)),
                    "label": label,
                    "source_kind": "synthetic",
                }
            )

    dataset = pd.DataFrame(rows)
    return dataset.loc[:, [*FEATURE_COLUMNS, "label", "source_kind"]]
