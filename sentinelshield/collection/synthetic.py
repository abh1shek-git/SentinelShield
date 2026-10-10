"""Small deterministic traffic scenarios for pipeline development."""

from __future__ import annotations

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
