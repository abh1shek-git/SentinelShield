from scapy.all import sniff
from scapy.layers.inet import IP

def process_packet(packet):
    if IP in packet:

        protocol_map = {
            1: "1 (ICMP)",
            6: "6 (TCP)",
            17: "17 (UDP)"
        }

        protocol = protocol_map.get(packet[IP].proto, "OTHER")

        print(
            f"Source: {packet[IP].src} | "
            f"Destination: {packet[IP].dst} | "
            f"Protocol: {protocol} | "
            f"Size={len(packet)} bytes"
        )

sniff(prn=process_packet, count=20)
