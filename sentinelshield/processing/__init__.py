"""Metadata extraction and time-window aggregation."""

from sentinelshield.processing.traffic import (
    PacketRecord,
    TrafficWindowFeatures,
    aggregate_windows,
    iter_aggregate_windows,
    read_pcap,
    record_from_packet,
)

__all__ = [
    "PacketRecord",
    "TrafficWindowFeatures",
    "aggregate_windows",
    "iter_aggregate_windows",
    "read_pcap",
    "record_from_packet",
]
