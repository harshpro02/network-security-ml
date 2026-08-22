"""Run Guardian over a capture and, if Suricata has already processed the same
file, print what each one found beside the other.

This is not a scoreboard. Suricata is a signature engine built to recognise
known malicious payloads on a real network segment. Guardian is four flow
statistics and a pair of counting rules. They are good at different things,
and the useful part of running both is seeing where each one is silent.

    python scripts/compare_detectors.py --pcap demo/demo_capture.pcap
    python scripts/compare_detectors.py --pcap X --suricata-log out/eve.json
"""
import argparse
import json
import sys
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from scapy.all import rdpcap  # noqa: E402

from src.model.behaviour import find_beacons, find_scans  # noqa: E402
from src.model.live_bridge import classify_flows, group_packets  # noqa: E402


def guardian(pcap):
    packets = rdpcap(str(pcap))
    flows = group_packets(packets)
    rows = classify_flows(flows)
    alerts = find_scans(packets) + find_beacons(flows)
    return {
        "packets": len(packets),
        "flows": len(rows),
        "model_flagged": sum(r["is_threat"] for r in rows),
        "alerts": alerts,
    }


def suricata(log_path):
    """Read Suricata's eve.json. Returns None when it was never run."""
    if not log_path:
        return None
    path = Path(log_path)
    if not path.exists():
        return None

    signatures = Counter()
    total = 0
    for line in path.read_text(errors="ignore").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("event_type") != "alert":
            continue
        total += 1
        signatures[event.get("alert", {}).get("signature", "unnamed")] += 1
    return {"alerts": total, "signatures": signatures}


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--pcap", default=str(REPO_ROOT / "demo" / "demo_capture.pcap"))
    ap.add_argument("--suricata-log", default=None)
    args = ap.parse_args()

    pcap = Path(args.pcap)
    if not pcap.exists():
        sys.exit(f"No such capture: {pcap}")

    g = guardian(pcap)
    s = suricata(args.suricata_log)

    print(f"capture   {pcap.name}")
    print(f"packets   {g['packets']:,}")
    print(f"flows     {g['flows']:,}")
    print()

    print("GUARDIAN")
    print(f"  per-flow model      {g['model_flagged']} of {g['flows']:,} conversations rated an attack")
    if g["alerts"]:
        for a in g["alerts"]:
            print(f"  behaviour layer     {a['kind']}: {a['detail']}")
    else:
        print("  behaviour layer     nothing")
    print()

    print("SURICATA")
    if s is None:
        print("  not run (pass --suricata-log to include it)")
    elif s["alerts"] == 0:
        print("  0 alerts")
        print("  Its default ruleset targets known malicious payloads. A TCP connect")
        print("  scan carries none, so there is no signature for it to match.")
    else:
        print(f"  {s['alerts']} alerts")
        for sig, n in s["signatures"].most_common(10):
            print(f"    {n:>5}  {sig}")

    print()
    print("Different tools, different evidence. Suricata inspects payloads for known")
    print("patterns. Guardian counts behaviour across flows. A scan with no payload is")
    print("invisible to the first and obvious to the second, and the reverse is true of")
    print("a known exploit delivered in a single request.")


if __name__ == "__main__":
    main()
