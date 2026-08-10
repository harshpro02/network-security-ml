"""Record a demo capture containing real port-scan traffic.

Runs a TCP connect scan against your own machine while sniffing, then saves
the result to demo/demo_capture.pcap and prints what the detector makes of it.

This exists to answer a question the CICIDS2017 numbers cannot: does the
detector actually fire on traffic our own code captured and featurised?

    # Windows: run from an Administrator terminal (packet capture needs it)
    python scripts/record_demo.py

The target defaults to this machine and is refused unless it is a private or
loopback address, so this cannot be pointed at someone else's network.
"""
import argparse
import ipaddress
import socket
import sys
import threading
import time
from pathlib import Path

from scapy.all import sniff, wrpcap

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

from src.model.live_bridge import classify_flows, group_packets  # noqa: E402

DEFAULT_PORTS = list(range(1, 1025))


def local_ip():
    """Best guess at this machine's LAN address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))   # no packets are actually sent
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def check_target(target):
    """Only ever scan our own machine or a private address."""
    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        sys.exit(f"'{target}' is not an IP address.")
    if not (addr.is_private or addr.is_loopback):
        sys.exit(f"Refusing to scan {target}: only private or loopback addresses are allowed.")
    return target


def scan(target, ports, delay=0.002):
    """A plain TCP connect scan. Most ports will refuse, which is the point -
    a burst of tiny short-lived flows is exactly the PortScan signature."""
    opened = []
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.05)
        try:
            if s.connect_ex((target, port)) == 0:
                opened.append(port)
        except OSError:
            pass
        finally:
            s.close()
        time.sleep(delay)
    return opened


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--target", default=None, help="defaults to this machine")
    ap.add_argument("--ports", type=int, default=1024, help="scan ports 1..N (default 1024)")
    ap.add_argument("--out", default=str(REPO_ROOT / "demo" / "demo_capture.pcap"))
    args = ap.parse_args()

    target = check_target(args.target or local_ip())
    ports = list(range(1, args.ports + 1))
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)

    print(f"target      {target}")
    print(f"ports       1-{args.ports}")
    print(f"output      {out}")
    print()

    captured = []
    stop = threading.Event()

    def capture():
        try:
            sniff(prn=captured.append, filter=f"host {target}",
                  stop_filter=lambda _: stop.is_set(), store=False)
        except PermissionError:
            print("ERROR: packet capture needs administrator privileges.")
            print("Close this, reopen the terminal as Administrator, and run it again.")
        except OSError as exc:
            print(f"ERROR: could not capture ({exc})")

    sniffer = threading.Thread(target=capture, daemon=True)
    sniffer.start()
    time.sleep(2)          # let the sniffer attach before generating traffic

    print("scanning...")
    started = time.time()
    opened = scan(target, ports)
    print(f"done in {time.time() - started:.1f}s, {len(opened)} open port(s): {opened[:10]}")

    time.sleep(2)          # let trailing packets arrive
    stop.set()
    sniffer.join(timeout=5)

    if not captured:
        sys.exit("\nNo packets captured. Run this from an Administrator terminal.")

    wrpcap(str(out), captured)
    print(f"\nsaved {len(captured)} packets to {out}")

    rows = classify_flows(group_packets(captured))
    flagged = [r for r in rows if r["is_threat"]]
    print(f"\n{len(rows)} flows scored, {len(flagged)} flagged")

    kinds = {}
    for r in flagged:
        k = r["attack_type"] or "generic ATTACK"
        kinds[k] = kinds.get(k, 0) + 1
    for kind, n in sorted(kinds.items(), key=lambda kv: -kv[1]):
        print(f"  {n:>5}  {kind}")

    if not flagged:
        print("\n  Nothing flagged. That is a real result worth writing down:")
        print("  the detector did not fire on scan traffic our own code captured.")


if __name__ == "__main__":
    main()
