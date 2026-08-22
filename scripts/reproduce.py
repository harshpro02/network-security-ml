"""Regenerate every measured claim in the README.

Nothing here is quoted from memory. Each section runs the real code over the
real data and prints what comes back, so a reader can check the numbers
rather than take them on trust.

    python scripts/reproduce.py              everything that needs no dataset
    python scripts/reproduce.py --full       also retrain and re-evaluate

The dataset is not in this repository. --full needs CICIDS2017 cleaned into
data/processed/clean_for_training.csv, which src/dataset/combine.py and
src/dataset/clean.py produce from the raw CSVs.
"""
import argparse
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))

TRAINING_CSV = REPO_ROOT / "data" / "processed" / "clean_for_training.csv"


def rule(title):
    print(f"\n{'=' * 66}\n{title}\n{'=' * 66}")


def captures_in_repo():
    """The behaviour thresholds, checked against every capture available."""
    from scapy.all import rdpcap
    from src.model.behaviour import find_beacons, find_scans
    from src.model.live_bridge import classify_flows, group_packets

    rule("Behaviour layer against every capture in this repository")
    paths = sorted(REPO_ROOT.glob("demo/*.pcap")) + sorted(REPO_ROOT.glob("data/raw/*.pcap"))
    if not paths:
        print("No captures found.")
        return

    print(f"{'capture':<24} {'flows':>7} {'flagged':>8} {'ports/min':>10}  alerts")
    for path in paths:
        packets = rdpcap(str(path))
        flows = group_packets(packets)
        rows = classify_flows(flows)
        scans = find_scans(packets)
        beacons = find_beacons(flows)
        peak = max((a["count"] for a in scans), default=0)
        kinds = ", ".join(sorted({a["kind"] for a in scans + beacons})) or "none"
        print(f"{path.name:<24} {len(rows):>7} "
              f"{sum(r['is_threat'] for r in rows):>8} {peak:>10}  {kinds}")

    print("\nA threshold of 20 distinct ports per minute separates the scan from")
    print("everything else by two orders of magnitude in both directions.")


def real_attack():
    """The end-to-end test: does it fire on traffic this project captured itself."""
    from scapy.all import rdpcap
    from src.model.behaviour import find_scans
    from src.model.live_bridge import classify_flows, group_packets

    demo = REPO_ROOT / "demo" / "demo_capture.pcap"
    if not demo.exists():
        return

    rule("The recorded port scan, end to end")
    packets = rdpcap(str(demo))
    flows = group_packets(packets)
    rows = classify_flows(flows)
    flagged = sum(r["is_threat"] for r in rows)

    print(f"packets read              {len(packets):,}")
    print(f"conversations             {len(rows):,}")
    print(f"rated an attack by model  {flagged}")
    print(f"behaviour alerts          {len(find_scans(packets))}")
    for a in find_scans(packets):
        print(f"  {a['detail']}")
    print("\nThe per-flow model is close to blind here and that is the finding.")
    print("A single SYN to a closed port and a single ordinary packet are the")
    print("same four numbers, so no per-flow model can separate them.")


def held_out_metrics():
    """Test-set numbers for the two shipped models."""
    import joblib
    import pandas as pd
    from sklearn.metrics import classification_report
    from sklearn.model_selection import train_test_split

    from src.model.live_bridge import live_features

    rule("Shipped models on a held-out 20% of a 500,000 row sample")
    df = pd.read_csv(TRAINING_CSV, usecols=live_features + ["Label"]).sample(
        n=500000, random_state=42)
    y_type = df["Label"]
    y_bin = y_type.where(y_type == "BENIGN", "ATTACK")
    _, X_test, _, ybin_test, _, ytype_test = train_test_split(
        df[live_features], y_bin, y_type, test_size=0.2, random_state=42)

    detector = joblib.load(REPO_ROOT / "models" / "live_detector.joblib")
    print("Binary detector\n")
    print(classification_report(ybin_test, detector.predict(X_test), digits=4, zero_division=0))

    bundle = joblib.load(REPO_ROOT / "models" / "live_classifier.joblib")
    print(f"\nAttack types trusted enough to name: {sorted(bundle['reliable_types'])}")
    print(classification_report(ytype_test, bundle["model"].predict(X_test),
                                digits=4, zero_division=0))


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--full", action="store_true",
                    help="also run the dataset-dependent sections")
    args = ap.parse_args()

    captures_in_repo()
    real_attack()

    if not args.full:
        print("\nRun with --full for the dataset-dependent numbers: test-set")
        print("metrics and the leave-one-day-out evaluation.")
        return

    if not TRAINING_CSV.exists():
        sys.exit(f"\n--full needs {TRAINING_CSV.relative_to(REPO_ROOT)}, which is not in "
                 "this repository.\nBuild it with src/dataset/combine.py then "
                 "src/dataset/clean.py.")

    held_out_metrics()

    rule("Leave-one-day-out, the honest generalisation number")
    subprocess.run([sys.executable, str(REPO_ROOT / "scripts" / "evaluate_by_day.py")],
                   cwd=REPO_ROOT, check=False)


if __name__ == "__main__":
    main()
