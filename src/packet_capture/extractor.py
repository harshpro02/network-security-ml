from scapy.all import rdpcap, IP, TCP, UDP
import pandas as pd
import sys

label = sys.argv[1] if len(sys.argv) > 1 else "001"

packets = rdpcap(f"data/raw/capture_{label}.pcap")

data = []

for packet in packets:
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto
        size = len(packet)
        
        src_port = 0
        dst_port = 0
        tcp_flags = ""
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            tcp_flags = str(packet[TCP].flags)
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
        
        data.append({
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "size": size,
            "tcp_flags": tcp_flags
        })
df = pd.DataFrame(data)
df.to_csv(f"data/raw/features_{label}.csv", index=False)

print(f"=== {label.upper()} ===")
print(f"Extracted {len(df)} packets")
print(f"Average packet size: {df['size'].mean():.0f} bytes")
print(f"Unique destination IPs: {df['dst_ip'].nunique()}")
print(f"Most common protocol: {df['protocol'].mode()[0]}")
print()