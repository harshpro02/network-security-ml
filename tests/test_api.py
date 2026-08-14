import io

import pytest
from fastapi.testclient import TestClient
from scapy.all import IP, TCP, wrpcap

from src.api import main
from src.api.main import app

client = TestClient(app)


@pytest.fixture
def pcap_bytes(tmp_path):
    packets = []
    for i in range(20):
        p = IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=4444, dport=80) / (b"x" * 400)
        p.time = 1_700_000_000.0 + i * 0.01
        packets.append(p)
    for i in range(3):
        p = IP(src="10.0.0.9", dst="10.0.0.5") / TCP(sport=80, dport=4444) / (b"y" * 60)
        p.time = 1_700_000_000.0 + i * 2.0
        packets.append(p)

    path = tmp_path / "sample.pcap"
    wrpcap(str(path), packets)
    return path.read_bytes()


def upload(data, filename="sample.pcap"):
    return client.post(
        "/api/analyze",
        files={"file": (filename, io.BytesIO(data), "application/octet-stream")},
    )


class TestBasics:
    def test_health(self):
        body = client.get("/api/health").json()
        assert body["status"] == "ok"
        assert set(body) >= {"status", "live_capture", "demo_available"}

    def test_dashboard_is_served(self):
        res = client.get("/")
        assert res.status_code == 200
        assert "guardian" in res.text.lower()


class TestAnalyse:
    def test_valid_capture_is_scored(self, pcap_bytes):
        res = upload(pcap_bytes)
        assert res.status_code == 200
        body = res.json()
        assert body["source"] == "upload"
        assert body["packets_read"] == 23
        assert body["flow_count"] >= 1
        assert body["threat_count"] <= body["flow_count"]

    def test_every_flow_has_the_full_contract(self, pcap_bytes):
        for flow in upload(pcap_bytes).json()["flows"]:
            assert set(flow) == {
                "source", "destination", "src_port", "dst_port", "protocol",
                "packets", "bytes", "duration_sec", "avg_packet_size",
                "verdict", "attack_type", "is_threat",
            }
            assert flow["verdict"] in {"BENIGN", "ATTACK"}
            assert flow["is_threat"] == (flow["verdict"] == "ATTACK")
            assert flow["attack_type"] is None or flow["is_threat"]

    def test_verdict_is_json_native_not_numpy(self, pcap_bytes):
        flow = upload(pcap_bytes).json()["flows"][0]
        assert isinstance(flow["verdict"], str)
        assert isinstance(flow["is_threat"], bool)
        assert isinstance(flow["packets"], int)

    def test_flagged_flows_are_returned_first(self, pcap_bytes):
        flows = upload(pcap_bytes).json()["flows"]
        threats = [i for i, f in enumerate(flows) if f["is_threat"]]
        if threats:
            assert threats == list(range(len(threats)))

    def test_flow_list_is_capped_but_counts_are_not(self, tmp_path):
        packets = []
        for port in range(1, main.MAX_FLOWS_RETURNED + 60):
            p = IP(src="10.0.0.5", dst="10.0.0.9") / TCP(sport=40000 + port, dport=port, flags="S")
            p.time = 1_700_000_000.0 + port * 0.001
            packets.append(p)
        path = tmp_path / "scan.pcap"
        wrpcap(str(path), packets)

        body = upload(path.read_bytes()).json()
        assert body["flow_count"] == len(packets)
        assert body["flows_returned"] == main.MAX_FLOWS_RETURNED
        assert len(body["flows"]) == main.MAX_FLOWS_RETURNED

    def test_scan_traffic_raises_a_behavioural_alert(self, tmp_path):
        packets = []
        for port in range(1, 400):
            p = IP(src="10.0.0.66", dst="10.0.0.9") / TCP(sport=40000, dport=port, flags="S")
            p.time = 1_700_000_000.0 + port * 0.001
            packets.append(p)
        path = tmp_path / "scan.pcap"
        wrpcap(str(path), packets)

        body = upload(path.read_bytes()).json()
        assert body["alert_count"] == 1
        alert = body["alerts"][0]
        assert alert["kind"] == "port_scan"
        assert alert["source"] == "10.0.0.66"
        assert alert["count"] == 399

    def test_ordinary_traffic_raises_no_alerts(self, pcap_bytes):
        body = upload(pcap_bytes).json()
        assert body["alert_count"] == 0
        assert body["alerts"] == []

    def test_rejects_wrong_extension(self, pcap_bytes):
        assert upload(pcap_bytes, "notes.txt").status_code == 400

    def test_rejects_empty_file(self):
        assert upload(b"").status_code == 400

    def test_rejects_oversized_file(self):
        res = upload(b"\x00" * (main.MAX_UPLOAD_BYTES + 1))
        assert res.status_code == 413

    def test_rejects_unparseable_file(self):
        res = upload(b"this is definitely not a pcap")
        assert res.status_code == 400
        assert "scapy" not in res.text.lower()
        assert "traceback" not in res.text.lower()

    def test_accepts_pcapng_extension(self, pcap_bytes):
        assert upload(pcap_bytes, "x.pcapng").status_code in (200, 400)


class TestLiveCapture:
    def test_scan_is_refused_when_disabled(self, monkeypatch):
        monkeypatch.setattr(main, "LIVE_CAPTURE_ENABLED", False)
        res = client.get("/api/scan")
        assert res.status_code == 503
        assert "disabled" in res.json()["detail"].lower()


class TestDemo:
    def test_demo_replays_the_bundled_capture(self):
        res = client.get("/api/demo")
        if res.status_code == 503:
            pytest.skip("no demo capture bundled in this build")
        body = res.json()
        assert body["source"] == "demo"
        assert body["packets_read"] > 0
