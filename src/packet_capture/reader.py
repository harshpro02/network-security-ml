from scapy.all import rdpcap

packets = rdpcap("data/raw/capture_001.pcap")

print(f"Loaded {len(packets)} packets from file")
print()
print("First 5 packets:")
for i, packet in enumerate(packets[:5]):
    print(f"Packet {i+1}: {packet.summary()}")