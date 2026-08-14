import json
import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from scapy.all import rdpcap, sniff

from src.model.live_bridge import FlowTable, classify_flows, group_packets
from src.model.behaviour import find_beacons, find_scans
from src.model.devices import find_new_devices, observe_devices

REPO_ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = Path(__file__).resolve().parent / "static"
DEMO_PCAP = REPO_ROOT / "demo" / "demo_capture.pcap"

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_SUFFIXES = {".pcap", ".pcapng"}
MAX_FLOWS_RETURNED = 200

LIVE_CAPTURE_ENABLED = os.getenv("ALLOW_LIVE_CAPTURE", "1") == "1"
CAPTURE_SECONDS = int(os.getenv("CAPTURE_SECONDS", "30"))

app = FastAPI(title="Guardian", description="ML network intrusion detection")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


KNOWN_DEVICES = REPO_ROOT / "data" / "known_devices.json"


def _load_known():
    try:
        return set(json.loads(KNOWN_DEVICES.read_text()))
    except (OSError, ValueError):
        return set()


def _remember(macs):
    """Best effort. A read-only host simply never builds a history, which
    means it reports no device as new rather than reporting all of them."""
    try:
        KNOWN_DEVICES.parent.mkdir(parents=True, exist_ok=True)
        KNOWN_DEVICES.write_text(json.dumps(sorted(_load_known() | set(macs))))
    except OSError:
        pass


def _payload(results, source, packets_read, alerts, devices=()):
    ordered = sorted(results, key=lambda r: (not r["is_threat"], -r["packets"]))

    # Flows are directional, so every conversation appears twice: once out to
    # the service port and once back from an ephemeral reply port. Charting
    # both draws each conversation twice and pins half the points at 60k+.
    # The lower port is the service side, which is the half worth plotting.
    points = [
        [r["started_at"], r["dst_port"], r["packets"], 1 if r["is_threat"] else 0]
        for r in results
        if r["dst_port"] <= r["src_port"]
    ]

    top = {}
    for r in results:
        top[r["destination"]] = top.get(r["destination"], 0) + r["bytes"]
    talkers = sorted(top.items(), key=lambda kv: -kv[1])[:8]

    return {
        "source": source,
        "packets_read": packets_read,
        "flow_count": len(results),
        "threat_count": sum(1 for r in results if r["is_threat"]),
        "flows_returned": min(len(results), MAX_FLOWS_RETURNED),
        "flows": ordered[:MAX_FLOWS_RETURNED],
        "alerts": alerts,
        "alert_count": len(alerts),
        "points": points,
        "talkers": [{"host": h, "bytes": b} for h, b in talkers],
        "devices": list(devices),
        "device_count": len(devices),
    }


def _verdicts_from_packets(packets, source):
    flows = group_packets(packets)
    return _payload(
        classify_flows(flows),
        source,
        len(packets),
        find_scans(packets) + find_beacons(flows),
        observe_devices(packets),
    )


@app.get("/")
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "live_capture": LIVE_CAPTURE_ENABLED,
        "demo_available": DEMO_PCAP.exists(),
    }


@app.get("/api/scan")
def scan():
    if not LIVE_CAPTURE_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Live capture is disabled on this host. Use the demo or upload a PCAP.",
        )

    table = FlowTable()
    captured = []

    def handle(packet):
        captured.append(packet)
        table.add(packet)

    try:
        sniff(prn=handle, timeout=CAPTURE_SECONDS)
    except PermissionError:
        raise HTTPException(
            status_code=503,
            detail="Live capture needs administrator privileges. Run locally as admin.",
        )
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Could not capture: {exc}")

    flows = table.finish()
    devices = observe_devices(captured)

    # Only a live capture is trustworthy evidence of who is on this network,
    # so only a live capture updates the history an upload is compared against.
    new_devices = find_new_devices(devices, _load_known())
    _remember(d["mac"] for d in devices)

    payload = _payload(
        classify_flows(flows),
        "live",
        table.packets_seen,
        find_scans(captured) + find_beacons(flows) + new_devices,
        devices,
    )
    payload["capture_seconds"] = CAPTURE_SECONDS
    return payload


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=400, detail="Upload a .pcap or .pcapng file.")

    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if not data:
        raise HTTPException(status_code=400, detail="That file is empty.")
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large. Limit is {MAX_UPLOAD_BYTES // 1024 // 1024} MB.",
        )

    tmp_path = None
    try:
        with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = tmp.name
        try:
            packets = rdpcap(tmp_path)
        except Exception:
            raise HTTPException(status_code=400, detail="Could not read that capture file.")
    finally:
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    return _verdicts_from_packets(packets, "upload")


@app.get("/api/demo")
def demo():
    if not DEMO_PCAP.exists():
        raise HTTPException(status_code=503, detail="No demo capture is bundled with this build.")

    return _verdicts_from_packets(rdpcap(str(DEMO_PCAP)), "demo")
