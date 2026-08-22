from scapy.all import sniff, IP, TCP, UDP
from pathlib import Path
import joblib
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = REPO_ROOT / "models" / "live_detector.joblib"
CLASSIFIER_PATH = REPO_ROOT / "models" / "live_classifier.joblib"

model = joblib.load(MODEL_PATH)

_bundle = joblib.load(CLASSIFIER_PATH)
type_model = _bundle["model"]
reliable_types = set(_bundle["reliable_types"])

live_features = ['Flow Duration', 'Total Fwd Packets', 'Total Length of Fwd Packets', 'Average Packet Size']

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


def conversation_key(packet):
    """Both directions of one exchange map to the same key.

    CICFlowMeter treats a conversation as a single bidirectional flow and then
    reports the two directions separately. Keying on the directional 5-tuple
    split every exchange in half, which double counted conversations and made
    Average Packet Size wrong, since that feature spans both directions.
    """
    key = get_flow_key(packet)
    if key is None:
        return None
    src_ip, dst_ip, src_port, dst_port, protocol = key
    a, b = (src_ip, src_port), (dst_ip, dst_port)
    return (a, b, protocol) if a <= b else (b, a, protocol)


def is_forward(packet, key):
    """True when the packet travels the way the conversation was opened."""
    k = get_flow_key(packet)
    return bool(k) and k[0] == key[0] and k[2] == key[2]


class FlowTable:
    def __init__(self, flow_timeout=FLOW_TIMEOUT):
        self.flow_timeout = flow_timeout
        self.packets_seen = 0
        self._open = {}
        self._closed = []

    def add(self, packet):
        self.packets_seen += 1
        pair = conversation_key(packet)
        if pair is None:
            return

        current = self._open.get(pair)
        if current is not None and float(packet.time) - float(current[1][0].time) > self.flow_timeout:
            self._closed.append(current)
            current = None

        if current is None:
            # Whoever sent the first packet defines the forward direction.
            current = self._open[pair] = (get_flow_key(packet), [])
        current[1].append(packet)

        if TCP in packet and int(packet[TCP].flags) & 0x05:
            self._closed.append(current)
            del self._open[pair]

    def finish(self):
        finished = self._closed + list(self._open.values())
        self._closed = []
        self._open = {}
        return finished


def payload_size(packet):
    if TCP in packet:
        return len(packet[TCP].payload)
    if UDP in packet:
        return len(packet[UDP].payload)
    if IP in packet:
        return len(packet[IP].payload)
    return len(packet)


def flow_to_features(packets, key=None):
    """Duration spans the whole conversation and Average Packet Size covers
    both directions, but the two Fwd columns count only the forward half,
    which is how CICIDS2017 defines them.

    With no key every packet is treated as forward, which is what a
    single-direction caller wants.
    """
    times = [float(p.time) for p in packets]
    duration = max(times) - min(times)

    sizes = [payload_size(p) for p in packets]
    avg_size = sum(sizes) / len(packets)

    if key is None:
        forward = sizes
    else:
        forward = [payload_size(p) for p in packets if is_forward(p, key)]
        if not forward:
            forward = sizes

    return duration, len(forward), sum(forward), avg_size


def make_feature_vector(duration, packet_count, total_bytes, avg_size):
    return pd.DataFrame(
        [[duration * 1_000_000, packet_count, total_bytes, avg_size]],
        columns=live_features,
    )


def group_packets(packets):
    table = FlowTable()
    for packet in packets:
        table.add(packet)
    return table.finish()


def classify_flows(flow_list, min_packets=1):
    kept = [(key, packets) for key, packets in flow_list if len(packets) >= min_packets]
    if not kept:
        return []

    features = [flow_to_features(packets, key) for key, packets in kept]
    frame = pd.DataFrame(
        [(duration * 1_000_000, count, total, avg) for duration, count, total, avg in features],
        columns=live_features,
    )
    verdicts = model.predict(frame)

    flagged = [i for i, v in enumerate(verdicts) if v == "ATTACK"]
    named = {}
    if flagged:
        for i, predicted in zip(flagged, type_model.predict(frame.iloc[flagged])):
            named[i] = str(predicted)

    starts = [min(float(p.time) for p in packets) for _, packets in kept]
    origin = min(starts)

    results = []
    for i, (key, _) in enumerate(kept):
        duration, count, total_bytes, avg_size = features[i]

        verdict = str(verdicts[i])
        is_threat = verdict == "ATTACK"

        attack_type = named.get(i)
        if attack_type not in reliable_types:
            attack_type = None

        results.append({
            "source": key[0],
            "destination": key[1],
            "src_port": key[2],
            "dst_port": key[3],
            "protocol": key[4],
            "packets": count,
            "bytes": total_bytes,
            "duration_sec": round(duration, 3),
            "started_at": round(starts[i] - origin, 3),
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
