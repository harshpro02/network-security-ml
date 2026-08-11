import os
import tempfile
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse
from scapy.all import rdpcap, sniff

from src.model.live_bridge import FlowTable, classify_flows, group_packets

REPO_ROOT = Path(__file__).resolve().parents[2]
STATIC_DIR = Path(__file__).resolve().parent / "static"
DEMO_PCAP = REPO_ROOT / "demo" / "demo_capture.pcap"

MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_SUFFIXES = {".pcap", ".pcapng"}
MAX_FLOWS_RETURNED = 200

LIVE_CAPTURE_ENABLED = os.getenv("ALLOW_LIVE_CAPTURE", "1") == "1"
CAPTURE_SECONDS = int(os.getenv("CAPTURE_SECONDS", "30"))

app = FastAPI(title="Guardian", description="ML network intrusion detection")


def _payload(results, source, packets_read):
    ordered = sorted(results, key=lambda r: (not r["is_threat"], -r["packets"]))
    return {
        "source": source,
        "packets_read": packets_read,
        "flow_count": len(results),
        "threat_count": sum(1 for r in results if r["is_threat"]),
        "flows_returned": min(len(results), MAX_FLOWS_RETURNED),
        "flows": ordered[:MAX_FLOWS_RETURNED],
    }


def _verdicts_from_packets(packets, source):
    return _payload(classify_flows(group_packets(packets)), source, len(packets))


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
    try:
        sniff(prn=table.add, timeout=CAPTURE_SECONDS)
    except PermissionError:
        raise HTTPException(
            status_code=503,
            detail="Live capture needs administrator privileges. Run locally as admin.",
        )
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Could not capture: {exc}")

    payload = _payload(classify_flows(table.finish()), "live", table.packets_seen)
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
