"""Extract privacy-conscious packet metadata and aggregate fixed windows."""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.packet import Packet
from scapy.utils import PcapNgReader, PcapReader


@dataclass(frozen=True, slots=True)
class PacketRecord:
    """One packet's headers and length; payload contents are never retained."""

    timestamp: float
    source_ip: str
    destination_ip: str
    protocol: str
    packet_bytes: int
    source_port: int | None = None
    destination_port: int | None = None
    tcp_flags: int = 0
    source_kind: str = "observed"
    scenario_label: str | None = None


@dataclass(frozen=True, slots=True)
class TrafficWindowFeatures:
    """Aggregate statistics for one aligned time window."""

    window_start: float
    window_seconds: float
    packet_count: int
    total_bytes: int
    packets_per_second: float
    bytes_per_second: float
    average_packet_bytes: float
    minimum_packet_bytes: int
    maximum_packet_bytes: int
    tcp_packets: int
    udp_packets: int
    icmp_packets: int
    other_packets: int
    syn_count: int
    syn_ack_count: int
    ack_count: int
    fin_count: int
    rst_count: int
    syn_ratio: float
    unique_sources: int
    unique_destinations: int
    unique_destination_ports: int
    unique_flows: int
    source_kind: str


def record_from_packet(packet: Packet, *, source_kind: str = "observed") -> PacketRecord | None:
    """Convert a Scapy packet to header metadata, or ignore unsupported packets."""
    if IP in packet:
        source_ip = packet[IP].src
        destination_ip = packet[IP].dst
    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        destination_ip = packet[IPv6].dst
    else:
        return None

    protocol = "other"
    source_port = None
    destination_port = None
    flags = 0
    if TCP in packet:
        protocol = "tcp"
        source_port = int(packet[TCP].sport)
        destination_port = int(packet[TCP].dport)
        flags = int(packet[TCP].flags)
    elif UDP in packet:
        protocol = "udp"
        source_port = int(packet[UDP].sport)
        destination_port = int(packet[UDP].dport)
    elif ICMP in packet or any(
        layer.__name__.startswith("ICMPv6") for layer in packet.layers()
    ):
        protocol = "icmp"

    timestamp = float(getattr(packet, "time", 0.0))
    return PacketRecord(
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        protocol=protocol,
        packet_bytes=len(packet),
        source_port=source_port,
        destination_port=destination_port,
        tcp_flags=flags,
        source_kind=source_kind,
    )


def read_pcap(path: str | Path) -> Iterator[PacketRecord]:
    """Yield metadata records from an authorized PCAP/PCAPNG file."""
    capture_path = Path(path)
    with capture_path.open("rb") as capture_file:
        magic = capture_file.read(4)
    reader_type = PcapNgReader if magic == b"\x0a\x0d\x0d\x0a" else PcapReader
    with reader_type(str(capture_path)) as reader:
        for packet in reader:
            record = record_from_packet(packet, source_kind="pcap")
            if record is not None:
                yield record


def aggregate_windows(
    records: Iterable[PacketRecord], window_seconds: float = 5.0
) -> list[TrafficWindowFeatures]:
    """Aggregate packet metadata into epoch-aligned windows.

    A TCP SYN ratio is initial SYN-only packets divided by all TCP packets. It is a signal,
    not evidence that traffic is malicious. TCP flags may be unavailable in
    some capture sources, in which case those counts are necessarily partial.
    """
    if window_seconds <= 0:
        raise ValueError("window_seconds must be greater than zero")

    buckets: dict[float, list[PacketRecord]] = defaultdict(list)
    for record in records:
        start = (record.timestamp // window_seconds) * window_seconds
        buckets[start].append(record)

    results: list[TrafficWindowFeatures] = []
    for start, packets in sorted(buckets.items()):
        tcp_packets = sum(packet.protocol == "tcp" for packet in packets)
        syn_count = sum(
            packet.protocol == "tcp"
            and bool(packet.tcp_flags & 0x02)
            and not bool(packet.tcp_flags & 0x10)
            for packet in packets
        )
        syn_ack_count = sum(
            packet.protocol == "tcp"
            and bool(packet.tcp_flags & 0x02)
            and bool(packet.tcp_flags & 0x10)
            for packet in packets
        )
        ack_count = sum(
            packet.protocol == "tcp" and bool(packet.tcp_flags & 0x10)
            for packet in packets
        )
        fin_count = sum(
            packet.protocol == "tcp" and bool(packet.tcp_flags & 0x01)
            for packet in packets
        )
        rst_count = sum(
            packet.protocol == "tcp" and bool(packet.tcp_flags & 0x04)
            for packet in packets
        )
        sizes = [packet.packet_bytes for packet in packets]
        flows = {
            (
                packet.source_ip,
                packet.destination_ip,
                packet.source_port,
                packet.destination_port,
                packet.protocol,
            )
            for packet in packets
        }
        source_kinds = {packet.source_kind for packet in packets}
        source_kind = source_kinds.pop() if len(source_kinds) == 1 else "mixed"
        packet_count = len(packets)
        total_bytes = sum(sizes)
        results.append(
            TrafficWindowFeatures(
                window_start=start,
                window_seconds=window_seconds,
                packet_count=packet_count,
                total_bytes=total_bytes,
                packets_per_second=packet_count / window_seconds,
                bytes_per_second=total_bytes / window_seconds,
                average_packet_bytes=total_bytes / packet_count,
                minimum_packet_bytes=min(sizes),
                maximum_packet_bytes=max(sizes),
                tcp_packets=tcp_packets,
                udp_packets=sum(packet.protocol == "udp" for packet in packets),
                icmp_packets=sum(packet.protocol == "icmp" for packet in packets),
                other_packets=sum(packet.protocol == "other" for packet in packets),
                syn_count=syn_count,
                syn_ack_count=syn_ack_count,
                ack_count=ack_count,
                fin_count=fin_count,
                rst_count=rst_count,
                syn_ratio=syn_count / tcp_packets if tcp_packets else 0.0,
                unique_sources=len({packet.source_ip for packet in packets}),
                unique_destinations=len({packet.destination_ip for packet in packets}),
                unique_destination_ports=len(
                    {
                        packet.destination_port
                        for packet in packets
                        if packet.destination_port is not None
                    }
                ),
                unique_flows=len(flows),
                source_kind=source_kind,
            )
        )
    return results
