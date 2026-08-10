"""Guardian API.

Three ways in, one detection path:

  /api/scan     live packet capture   - needs admin, local only
  /api/analyze  upload a PCAP         - no privileges, runs anywhere
  /api/demo     replay a bundled PCAP - no privileges, runs anywhere

Live capture is the reason this tool exists, but a cloud host has no
meaningful traffic to watch, so the hosted build serves the other two.
"""
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

# Untrusted input: cap the size and the shapes we will hand to the parser.
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
ALLOWED_SUFFIXES = {".pcap", ".pcapng"}

# Cloud deploys set this to 0 so /api/scan fails with a clear message
# instead of a confusing permission error.
LIVE_CAPTURE_ENABLED = os.getenv("ALLOW_LIVE_CAPTURE", "1") == "1"
# 5 seconds was too short to be useful: most attack flows in CICIDS2017 run
# longer than that, so a 5s window could never reproduce their shape.
CAPTURE_SECONDS = int(os.getenv("CAPTURE_SECONDS", "30"))

app = FastAPI(title="Guardian", description="ML network intrusion detection")


def _verdicts_from_packets(packets):
    results = classify_flows(group_packets(packets))
    return {
        "flows": results,
        "flow_count": len(results),
        "threat_count": sum(1 for r in results if r["is_threat"]),
    }


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
    """Sniff the local interface, then score whatever flows appear."""
    if not LIVE_CAPTURE_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Live capture is disabled on this host. Use the demo or upload a PCAP.",
        )

    # Each request gets its own table, so concurrent scans cannot mix packets.
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

    results = classify_flows(table.finish())
    return {
        "source": "live",
        "capture_seconds": CAPTURE_SECONDS,
        "flows": results,
        "flow_count": len(results),
        "threat_count": sum(1 for r in results if r["is_threat"]),
    }


@app.post("/api/analyze")
async def analyze(file: UploadFile = File(...)):
    """Score an uploaded capture. No privileges needed, so this is what
    the hosted build actually runs."""
    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in ALLOWED_SUFFIXES:
        raise HTTPException(status_code=400, detail="Upload a .pcap or .pcapng file.")

    # Read one byte past the limit so an oversized file is detected
    # without pulling the whole thing into memory.
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
            # Never surface parser internals for attacker-supplied input.
            raise HTTPException(status_code=400, detail="Could not read that capture file.")
    finally:
        # Best-effort cleanup. On Windows a failed parse can leave scapy
        # holding the handle, and unlink would then mask the real error.
        if tmp_path:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    payload = _verdicts_from_packets(packets)
    payload["source"] = "upload"
    payload["packets_read"] = len(packets)
    return payload


@app.get("/api/demo")
def demo():
    """Replay a recorded capture through the same detection path.

    Real packets and real verdicts, just read from disk instead of a NIC.
    The dashboard labels this as a replay.
    """
    if not DEMO_PCAP.exists():
        raise HTTPException(status_code=503, detail="No demo capture is bundled with this build.")

    packets = rdpcap(str(DEMO_PCAP))
    payload = _verdicts_from_packets(packets)
    payload["source"] = "demo"
    payload["packets_read"] = len(packets)
    return payload
