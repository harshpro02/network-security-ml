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
import re
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


def rules_loaded(eve_path):
    """How many rules Suricata actually had.

    Zero alerts means nothing if the ruleset never loaded, so this is not
    optional detail. Suricata records the count in its own log next to eve.json.
    """
    log = Path(eve_path).parent / "suricata.log"
    if not log.exists():
        return None
    match = re.search(r"([\d,]+) rules successfully loaded", log.read_text(errors="ignore"))
    return int(match.group(1).replace(",", "")) if match else None


def suricata(log_path):
    """Read Suricata's eve.json. Returns None when it was never run."""
    if not log_path:
        return None
    path = Path(log_path)
    if not path.exists():
        return None

    signatures = Counter()
    total = 0
    events = Counter()
    for line in path.read_text(errors="ignore").splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        kind = event.get("event_type")
        events[kind] += 1
        if kind != "alert":
            continue
        total += 1
        signatures[event.get("alert", {}).get("signature", "unnamed")] += 1
    return {
        "alerts": total,
        "signatures": signatures,
        "events": events,
        "rules": rules_loaded(path),
    }


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
    else:
        rules = s["rules"]
        print(f"  rules loaded        {rules:,}" if rules is not None
              else "  rules loaded        unknown, suricata.log not found")
        print(f"  events logged       {sum(s['events'].values()):,} "
              f"({', '.join(f'{k} {v}' for k, v in s['events'].most_common(4))})")
        print(f"  alerts              {s['alerts']}")

        for sig, n in s["signatures"].most_common(10):
            print(f"    {n:>5}  {sig}")

        if not rules:
            print()
            print("  WARNING: no ruleset was loaded, so zero alerts says nothing about")
            print("  Suricata. This comparison is not valid until suricata-update runs.")
        elif s["alerts"] == 0:
            print()
            print(f"  {rules:,} signatures were loaded and none matched. They look for known")
            print("  malicious payloads, and a TCP connect scan carries no payload at all.")
            print("  Suricata parsed the traffic fine, it just has nothing to match on.")

    print()
    print("Different tools, different evidence. Suricata inspects payloads for known")
    print("patterns. Guardian counts behaviour across flows. A scan with no payload is")
    print("invisible to the first and obvious to the second, and the reverse is true of")
    print("a known exploit delivered in a single request.")


if __name__ == "__main__":
    main()
