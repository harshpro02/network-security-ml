import statistics
from collections import defaultdict

from scapy.all import IP, TCP, UDP

SCAN_WINDOW = 60.0
PORT_THRESHOLD = 20
HOST_THRESHOLD = 20

BEACON_MIN_CONNECTIONS = 6
BEACON_MAX_JITTER = 0.15
BEACON_MIN_INTERVAL = 2.0


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


def find_beacons(flow_list,
                 min_connections=BEACON_MIN_CONNECTIONS,
                 max_jitter=BEACON_MAX_JITTER,
                 min_interval=BEACON_MIN_INTERVAL):
    starts = defaultdict(list)
    for key, packets in flow_list:
        src, dst = key[0], key[1]
        starts[(src, dst, key[3])].append(min(float(p.time) for p in packets))

    alerts = []
    for (src, dst, dport), times in starts.items():
        if len(times) < min_connections:
            continue

        times.sort()
        gaps = [b - a for a, b in zip(times, times[1:])]
        mean = statistics.fmean(gaps)
        if mean < min_interval:
            continue

        jitter = statistics.pstdev(gaps) / mean
        if jitter > max_jitter:
            continue

        alerts.append({
            "kind": "beacon",
            "source": src,
            "target": dst,
            "port": dport,
            "count": len(times),
            "interval_seconds": round(mean, 1),
            "jitter": round(jitter, 3),
            "detail": (f"{src} contacted {dst}:{dport} {len(times)} times at a "
                       f"steady {mean:.0f}s interval, jitter {jitter:.0%}"),
        })

    alerts.sort(key=lambda a: (a["jitter"], -a["count"]))
    return alerts
