from scapy.all import sniff, IP, TCP, UDP
import time

flows = {}

def get_flow_key(packet):
    if IP not in packet:
        return None
    
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = packet[IP].proto
    
    src_port = 0
    dst_port = 0
    if TCP in packet:
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    
    return (src_ip, dst_ip, src_port, dst_port, protocol)

def process_packet(packet):
    key = get_flow_key(packet)
    if key is None:
        return
    
    if key not in flows:
        flows[key] = []
    
    flows[key].append(packet)

def flow_to_features(packets):
    times = [float(p.time) for p in packets]
    sizes = [len(p) for p in packets]
    
    duration = max(times) - min(times)
    packet_count = len(packets)
    total_bytes = sum(sizes)
    avg_size = total_bytes / packet_count
    
    return duration, packet_count, total_bytes, avg_size

print("Capturing packets for 30 seconds...")
sniff(prn=process_packet, timeout=30)
print(f"Captured {len(flows)} flows")

print("\n=== TOP 5 FLOWS ===")
sorted_flows = sorted(flows.items(), key=lambda x: len(x[1]), reverse=True)
for key, packets in sorted_flows[:5]:
    duration, count, total_bytes, avg_size = flow_to_features(packets)
    print(f"{key[0]} -> {key[1]} | {count} packets | {total_bytes} bytes | avg {avg_size:.0f}B | {duration:.1f}s")