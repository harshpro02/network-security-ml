"""Record traffic from this machine to a PCAP.

    python scripts/capture.py --label browsing --packets 300

Capture needs Npcap on Windows or libpcap elsewhere, and on most systems
administrator rights. Files land in data/raw/ and are gitignored.
"""
import argparse
from pathlib import Path

from scapy.all import sniff, wrpcap

REPO_ROOT = Path(__file__).resolve().parents[1]


def capture(label, count, seconds):
    out = REPO_ROOT / "data" / "raw" / f"capture_{label}.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"Capturing up to {count} packets or {seconds}s, whichever comes first")
    packets = sniff(count=count, timeout=seconds)
    if not packets:
        raise SystemExit("Captured nothing. Administrator rights are usually the reason.")

    wrpcap(str(out), packets)
    span = max(float(p.time) for p in packets) - min(float(p.time) for p in packets)
    print(f"Wrote {len(packets)} packets spanning {span:.1f}s to {out.relative_to(REPO_ROOT)}")
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--label", default="general", help="names the output file")
    ap.add_argument("--packets", type=int, default=300)
    ap.add_argument("--seconds", type=int, default=60)
    args = ap.parse_args()
    capture(args.label, args.packets, args.seconds)
