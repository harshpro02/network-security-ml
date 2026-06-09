from scapy.all import sniff, wrpcap
import sys

label = sys.argv[1] if len(sys.argv) > 1 else "general"

print(f"Starting capture for: {label}")
print("Capturing 300 packets. Go do the activity now.")

packets = sniff(count=300)

print(f"Captured {len(packets)} packets")

filename = f"data/raw/capture_{label}.pcap"
wrpcap(filename, packets)

print(f"Saved to {filename}")