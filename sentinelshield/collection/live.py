"""Short, opt-in live packet metadata capture."""

from __future__ import annotations

from hashlib import sha256
import time

from scapy.all import get_if_list, sniff
from scapy.packet import Packet

from sentinelshield.processing.traffic import PacketRecord, record_from_packet


MAX_CAPTURE_SECONDS = 60


def list_capture_interfaces() -> list[str]:
    """Return interfaces Scapy can see, sorted for a stable UI list."""
    return sorted(set(get_if_list()))


def capture_live_metadata(
    interface: str, duration_seconds: int
) -> tuple[list[PacketRecord], str]:
    """Capture for a bounded interval and keep header metadata only.

    The callback converts each packet immediately. Scapy's packet store is disabled,
    so this function never retains full packet objects or payloads.
    """
    if not interface.strip():
        raise ValueError("a capture interface must be selected")
    if not 1 <= duration_seconds <= MAX_CAPTURE_SECONDS:
        raise ValueError(
            f"capture duration must be between 1 and {MAX_CAPTURE_SECONDS} seconds"
        )

    capture_id = sha256(f"{interface}:{time.time_ns()}".encode()).hexdigest()[:12]
    source_kind = f"live:{capture_id}"
    records: list[PacketRecord] = []

    def collect(packet: Packet) -> None:
        record = record_from_packet(packet, source_kind=source_kind)
        if record is not None:
            records.append(record)

    sniff(
        iface=interface,
        timeout=duration_seconds,
        prn=collect,
        store=False,
    )
    return records, source_kind
