"""Small deterministic traffic scenarios for pipeline development."""

from __future__ import annotations

import math
import random

from sentinelshield.processing.traffic import PacketRecord


def make_synthetic_scenario(name: str) -> list[PacketRecord]:
    """Return marked synthetic metadata for a benign or SYN-heavy scenario."""
    if name not in {"normal", "syn_heavy"}:
        raise ValueError("scenario must be 'normal' or 'syn_heavy'")

    packets: list[PacketRecord] = []
    for index in range(10):
        if name == "syn_heavy":
            flags = 0x02
            source_ip = "192.0.2.10"
        else:
            flags = [0x02, 0x12, 0x10, 0x10, 0x11][index % 5]
            source_ip = f"192.0.2.{10 + index % 3}"
        packets.append(
            PacketRecord(
                timestamp=1000.0 + index * 0.1,
                source_ip=source_ip,
                destination_ip="198.51.100.20",
                protocol="tcp",
                packet_bytes=60 + (index % 3) * 10,
                source_port=40000 + index,
                destination_port=443,
                tcp_flags=flags,
                source_kind="synthetic",
                scenario_label=name,
            )
        )
    return packets


def make_synthetic_stream(
    *, window_count: int = 30, window_seconds: float = 5.0, scenario: str = "mixed"
) -> list[PacketRecord]:
    """Create deterministic multi-window metadata for dashboard demonstrations.

    ``mixed`` includes normal, high-volume UDP, SYN-heavy, and combined
    high-volume/SYN-heavy phases. It is fabricated training/demo data, not a
    packet replay and not a realistic attack simulation.
    """
    if window_count < 1:
        raise ValueError("window_count must be at least one")
    if not math.isfinite(window_seconds) or window_seconds <= 0:
        raise ValueError("window_seconds must be finite and greater than zero")
    if scenario not in {"mixed", "normal", "syn_surge"}:
        raise ValueError("scenario must be 'mixed', 'normal', or 'syn_surge'")

    rng = random.Random(42)
    first_window = math.ceil(1000.0 / window_seconds) * window_seconds
    records: list[PacketRecord] = []
    for window_index in range(window_count):
        if scenario == "normal" or (scenario == "mixed" and window_index < 8):
            pps = rng.randint(20, 30)
            tcp_share, syn_share, source_count = 0.60, 0.15, 5
        elif scenario == "syn_surge" or (scenario == "mixed" and 14 <= window_index < 20):
            pps = rng.randint(70, 90)
            tcp_share, syn_share, source_count = 0.92, 0.94, 2
        elif scenario == "mixed" and 8 <= window_index < 14:
            pps = rng.randint(110, 130)
            tcp_share, syn_share, source_count = 0.18, 0.20, 12
        elif scenario == "mixed" and 20 <= window_index < 24:
            pps = rng.randint(160, 185)
            tcp_share, syn_share, source_count = 0.90, 0.94, 25
        else:
            pps = rng.randint(20, 30)
            tcp_share, syn_share, source_count = 0.60, 0.15, 5

        packet_count = max(1, round(pps * window_seconds))
        tcp_count = round(packet_count * tcp_share)
        syn_count = round(tcp_count * syn_share)
        window_start = first_window + window_index * window_seconds
        for packet_index in range(packet_count):
            is_tcp = packet_index < tcp_count
            flags = 0
            if is_tcp:
                flags = 0x02 if packet_index < syn_count else rng.choice([0x10, 0x10, 0x11, 0x14])
            records.append(
                PacketRecord(
                    timestamp=window_start
                    + (packet_index / packet_count) * window_seconds,
                    source_ip=f"192.0.2.{1 + rng.randrange(source_count)}",
                    destination_ip=f"198.51.100.{1 + rng.randrange(4)}",
                    protocol="tcp" if is_tcp else "udp",
                    packet_bytes=rng.randint(60, 120),
                    source_port=rng.randint(1024, 65535),
                    destination_port=rng.choice([53, 80, 443, 8080]),
                    tcp_flags=flags,
                    source_kind="synthetic",
                    scenario_label=scenario,
                )
            )
    return records
