from collections import defaultdict

from scapy.all import IP, TCP, UDP

SCAN_WINDOW = 60.0
PORT_THRESHOLD = 20
HOST_THRESHOLD = 20


def _endpoints(packet):
    if IP not in packet:
        return None
    if TCP in packet:
        return packet[IP].src, packet[IP].dst, packet[TCP].dport
    if UDP in packet:
        return packet[IP].src, packet[IP].dst, packet[UDP].dport
    return None


def find_scans(packets, window=SCAN_WINDOW,
               port_threshold=PORT_THRESHOLD,
               host_threshold=HOST_THRESHOLD):
    ports = defaultdict(set)
    hosts = defaultdict(set)

    for packet in packets:
        ends = _endpoints(packet)
        if ends is None:
            continue
        src, dst, dport = ends
        bucket = int(float(packet.time) // window)
        ports[(src, dst, bucket)].add(dport)
        hosts[(src, bucket)].add(dst)

    peaks = {}

    for (src, dst, _), dports in ports.items():
        if len(dports) < port_threshold:
            continue
        key = ("port_scan", src, dst)
        if len(dports) > peaks.get(key, (0,))[0]:
            peaks[key] = (len(dports), None)

    for (src, _), dsts in hosts.items():
        if len(dsts) < host_threshold:
            continue
        key = ("host_sweep", src, None)
        if len(dsts) > peaks.get(key, (0,))[0]:
            peaks[key] = (len(dsts), None)

    alerts = []
    for (kind, src, dst), (count, _) in peaks.items():
        if kind == "port_scan":
            detail = (f"{src} contacted {count} distinct ports on {dst} "
                      f"within {int(window)}s")
        else:
            detail = (f"{src} contacted {count} distinct hosts "
                      f"within {int(window)}s")
        alerts.append({
            "kind": kind,
            "source": src,
            "target": dst,
            "count": count,
            "window_seconds": int(window),
            "detail": detail,
        })

    alerts.sort(key=lambda a: -a["count"])
    return alerts
