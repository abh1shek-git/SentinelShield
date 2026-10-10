# Traffic feature definitions

This document describes the current packet and window features. They summarize packet metadata; they do not identify intent or prove a DDoS attack.

## Input record

`PacketRecord` stores a capture timestamp, source/destination IP addresses, transport protocol, packet length, optional transport ports, TCP flags, and a source marker (`pcap:<capture-id>`, `live:<capture-id>`, `synthetic`, or `observed`). It does not store packet payload. Unsupported non-IP packets are skipped. Live capture extracts metadata in the packet callback and calls Scapy with packet storage disabled.

Offline capture reading supports classic PCAP and PCAPNG files. The file is streamed packet by packet; records are emitted only when an IPv4 or IPv6 header is present.

## Window features

Windows are aligned to epoch multiples of the configured duration (five seconds by default). A feature row describes all records in one window:

| Feature | Definition |
| --- | --- |
| Packet count / total bytes | Number of packet records / sum of captured packet lengths. |
| Packets per second / bytes per second | Window count / configured window duration. Rates use the full configured duration, including partial final windows. |
| Packet size statistics | Mean, minimum, and maximum packet length. |
| Protocol counts | TCP, UDP, ICMP (including recognized ICMPv6 layers), and other IPv4/IPv6 packets. |
| SYN count | TCP packets with SYN set and ACK clear; SYN-ACK is counted separately. |
| SYN ratio | Initial SYN count divided by all TCP packets; zero when the window has no TCP packets. |
| ACK / FIN / RST counts | TCP packets with each respective bit set. A packet may count toward multiple flags. |
| Unique sources/destinations/ports | Distinct IPs and non-null destination transport ports within the window. |
| Unique flows | Distinct five-tuples: source IP, destination IP, source port, destination port, protocol. |

TCP flags can be missing when capture data is incomplete or the packet is not decoded as TCP. A high SYN ratio is only one signal and may be seen in legitimate connection bursts.

## Synthetic scenarios

`make_synthetic_scenario("normal")` and `make_synthetic_scenario("syn_heavy")` return small deterministic examples with `source_kind="synthetic"` and a scenario label. `make_synthetic_stream()` creates a 30-window dashboard demonstration with normal, unusual-rate, SYN-heavy, and combined phases. These are pipeline fixtures, not realistic attack simulations or evaluation results.

## Detection outputs and limits

The rule detector computes an adaptive packet-rate threshold and explanatory decision for each window; these are results, not columns in the 21-feature ML schema. The optional dashboard ML comparison uses a separately trained synthetic-only model. Per-flow duration, inter-arrival summaries, source-to-destination distributions, per-source rolling baselines, and classifier probability calibration are not implemented.
