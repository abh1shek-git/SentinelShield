# Bounded live capture

The dashboard supports a single, explicitly started capture on a selected interface. It is disabled by default; switching the input selector does not itself capture packets.

## Start a capture

1. Start the dashboard using the command in the [demo guide](DEMO_GUIDE.md).
2. Choose **Live capture (opt-in)**.
3. Select an interface whose traffic you are authorized to monitor.
4. Check the authorization statement and choose a duration from 5 to 60 seconds.
5. Click **Start bounded capture**. The dashboard waits for that capture to finish before analyzing the results.

On Windows, Scapy may require Npcap and suitable permissions for the chosen interface. If no interfaces appear or capture fails, install/configure Npcap and check permissions. Do not select a network you do not have permission to monitor.

## Data handling

Scapy's packet store is disabled. During capture, a callback immediately converts supported IPv4/IPv6 packets into timestamp, addresses, protocol, length, ports, and TCP flags. Packet payload bytes and full Scapy packet objects are not retained by the collector. Non-IP packets are skipped.

The dashboard keeps the derived per-packet metadata in memory for the current session so it can rebuild windows if the aggregation duration changes. SQLite stores aggregate window features and alert reasons, not raw packet records or a PCAP. The capture source marker is a generated identifier rather than the interface name. Closing the dashboard session drops the in-memory packet metadata.

The current implementation does not configure a packet filter, write a PCAP, monitor continuously, or change firewall settings. This short capture is useful for demonstrating data flow and detector behavior; it does not provide network-wide visibility or validated attack detection.

## Empty captures

An empty result can mean there was no visible traffic during the selected interval, the selected interface was idle, or traffic was not decoded as IPv4/IPv6. Check the interface selection and permissions, then use an appropriate authorized host workload if you need to demonstrate traffic. Do not generate traffic against third-party systems.
