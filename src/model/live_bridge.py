from scapy.all import sniff, IP, TCP, UDP
import time
import joblib
import pandas as pd
import numpy as np

model = joblib.load("models/attack_detector.joblib")
columns = pd.read_csv("data/processed/clean_for_training.csv", nrows=0).columns.drop('Label')

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

def make_feature_vector(duration, packet_count, total_bytes, avg_size):
    vec = pd.DataFrame(np.zeros((1, len(columns))), columns=columns)
    
    vec['Flow Duration'] = duration * 1_000_000
    vec['Total Fwd Packets'] = packet_count
    vec['Total Length of Fwd Packets'] = total_bytes
    vec['Average Packet Size'] = avg_size
    
    return vec

print("Capturing packets for 30 seconds...")
sniff(prn=process_packet, timeout=30)
print(f"Captured {len(flows)} flows")

print("\n=== LIVE VERDICTS ===")
for key, packets in flows.items():
    if len(packets) < 5:
        continue
    
    duration, count, total_bytes, avg_size = flow_to_features(packets)
    vec = make_feature_vector(duration, count, total_bytes, avg_size)
    verdict = model.predict(vec)[0]
    
    print(f"{key[0]} -> {key[1]} | {count} pkts | {verdict}")