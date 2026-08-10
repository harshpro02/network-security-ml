from scapy.all import sniff, IP, TCP, UDP
from pathlib import Path
import joblib
import pandas as pd

# Resolve the models relative to this file, not the working directory,
# so the API works from any cwd and inside Docker.
REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "live_detector.joblib"
CLASSIFIER_PATH = REPO_ROOT / "models" / "live_classifier.joblib"

# Binary BENIGN/ATTACK. This is the verdict we trust.
model = joblib.load(MODEL_PATH)

# Names the attack type, but only for classes measured as precise at
# training time. Everything else stays a generic ATTACK. See train_live.py.
_bundle = joblib.load(CLASSIFIER_PATH)
type_model = _bundle["model"]
reliable_types = set(_bundle["reliable_types"])
live_features = ['Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets', 'Average Packet Size']

# CICFlowMeter, which produced the CICIDS2017 rows this model was trained on,
# expires a flow after 120 seconds. Matching that matters: if we let a flow run
# forever, its duration and packet count drift away from anything the model saw
# in training, and the verdict stops meaning what it meant on the test set.
FLOW_TIMEOUT = 120.0

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

class FlowTable:
    """Groups packets into flows, and closes them the way CICFlowMeter does.

    A flow ends when either:
      - 120 seconds have passed since its first packet, or
      - TCP tears it down with a FIN or a RST.

    Long-lived conversations therefore produce several flows over time rather
    than one ever-growing one. Each instance owns its own state, so concurrent
    requests cannot corrupt each other's capture.
    """

    def __init__(self, flow_timeout=FLOW_TIMEOUT):
        self.flow_timeout = flow_timeout
        self._open = {}     # key -> packets of the flow currently being built
        self._closed = []   # (key, packets) for flows that have ended

    def add(self, packet):
        key = get_flow_key(packet)
        if key is None:
            return

        current = self._open.get(key)
        if current is not None and float(packet.time) - float(current[0].time) > self.flow_timeout:
            self._closed.append((key, current))
            current = None

        if current is None:
            current = self._open[key] = []
        current.append(packet)

        # FIN (0x01) or RST (0x04) ends the conversation.
        if TCP in packet and int(packet[TCP].flags) & 0x05:
            self._closed.append((key, current))
            del self._open[key]

    def finish(self):
        """Close every still-open flow and return them all."""
        finished = self._closed + list(self._open.items())
        self._closed = []
        self._open = {}
        return finished

def flow_to_features(packets):
    times = [float(p.time) for p in packets]
    sizes = [len(p) for p in packets]
    
    duration = max(times) - min(times)
    packet_count = len(packets)
    total_bytes = sum(sizes)
    avg_size = total_bytes / packet_count
    
    return duration, packet_count, total_bytes, avg_size

def make_feature_vector(duration, packet_count, total_bytes, avg_size):
    vec = pd.DataFrame([[
        duration * 1_000_000,
        packet_count,
        total_bytes,
        avg_size
    ]], columns=live_features)
    
    return vec

def group_packets(packets):
    """Group an existing list of packets (from a PCAP) into finished flows."""
    table = FlowTable()
    for packet in packets:
        table.add(packet)
    return table.finish()

def classify_flows(flow_list, min_packets=1):
    """Score every flow with enough packets. Shared by live capture,
    PCAP upload, and demo replay so all three use one code path.

    min_packets used to be 5, which turned out to be actively harmful.
    Attack flows in CICIDS2017 are small: median 3 packets, 99th percentile
    12. A 5-packet floor silently discarded 62% of all attack traffic and
    99.9% of PortScan, the class the model is most precise on. Dropping it
    to 1 recovers that and cost 1 false positive across 1000 packets of
    real benign capture, so the floor was buying nothing.
    """
    results = []
    for key, packets in flow_list:
        if len(packets) < min_packets:
            continue

        duration, count, total_bytes, avg_size = flow_to_features(packets)
        vec = make_feature_vector(duration, count, total_bytes, avg_size)

        # str() so values are JSON-serializable, not numpy scalars
        verdict = str(model.predict(vec)[0])
        is_threat = verdict == "ATTACK"

        # Only name the attack when the type model is trustworthy for that
        # class. Otherwise the flow stays a generic ATTACK.
        attack_type = None
        if is_threat:
            predicted = str(type_model.predict(vec)[0])
            if predicted in reliable_types:
                attack_type = predicted

        results.append({
            "source": key[0],
            "destination": key[1],
            "src_port": key[2],
            "dst_port": key[3],
            "protocol": key[4],
            "packets": count,
            "bytes": total_bytes,
            "duration_sec": round(duration, 3),
            "avg_packet_size": round(avg_size, 1),
            "verdict": verdict,
            "attack_type": attack_type,
            "is_threat": is_threat,
        })
    return results

def run_capture(seconds=30):
    print(f"Capturing packets for {seconds} seconds...")
    table = FlowTable()
    sniff(prn=table.add, timeout=seconds)
    flows = table.finish()
    print(f"Captured {len(flows)} flows")

    print("\n=== LIVE VERDICTS ===")
    for row in classify_flows(flows):
        label = row['attack_type'] or row['verdict']
        print(f"{row['source']} -> {row['destination']} | {row['packets']} pkts | {label}")

if __name__ == "__main__":
    import sys
    run_capture(int(sys.argv[1]) if len(sys.argv) > 1 else 30)