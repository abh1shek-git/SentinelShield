from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from collections import defaultdict
import time

# Threshold for suspicious traffic in 5 seconds
THRESHOLD = 500

# Store total packets from each IP
packet_count = defaultdict(int)

# Store SYN packets from each IP
syn_count = defaultdict(int)

start_time = time.time()


def process_packet(packet):
    global start_time

    if IP in packet:
        src_ip = packet[IP].src

        # Count every packet
        packet_count[src_ip] += 1

        # Count SYN packets
        if TCP in packet:
            if packet[TCP].flags == "S":
                syn_count[src_ip] += 1

        current_time = time.time()

        # Print statistics every 5 seconds
        if current_time - start_time >= 5:

            print("\nPackets received in last 5 seconds:")
            print("-" * 50)

            for ip, count in packet_count.items():

                syn = syn_count[ip]

                if count > 0:
                    syn_ratio = (syn / count) * 100
                else:
                    syn_ratio = 0

                print(
                    f"{ip} -> "
                    f"{count} packets | "
                    f"SYN={syn} | "
                    f"SYN Ratio={syn_ratio:.2f}%"
                )

                # Detection logic
                if count > THRESHOLD and syn_ratio > 70:
                    print(
                        f"🚨 POSSIBLE SYN FLOOD ATTACK DETECTED "
                        f"FROM {ip}"
                    )

            # Reset counters for next window
            packet_count.clear()
            syn_count.clear()
            start_time = current_time


print("Starting packet capture...")
print("Press Ctrl + C to stop.\n")

sniff(
    prn=process_packet,
    store=False
)