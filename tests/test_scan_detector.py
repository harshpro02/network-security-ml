from scapy.all import IP, TCP, UDP

from src.model.scan_detector import find_scans


def tcp(src="10.0.0.66", dst="10.0.0.9", dport=80, t=0.0):
    p = IP(src=src, dst=dst) / TCP(sport=40000, dport=dport, flags="S")
    p.time = t
    return p


class TestPortScan:
    def test_many_ports_on_one_host_is_a_scan(self):
        packets = [tcp(dport=p, t=p * 0.01) for p in range(1, 200)]
        alerts = find_scans(packets)
        assert len(alerts) == 1
        assert alerts[0]["kind"] == "port_scan"
        assert alerts[0]["source"] == "10.0.0.66"
        assert alerts[0]["target"] == "10.0.0.9"
        assert alerts[0]["count"] == 199

    def test_a_few_ports_is_not_a_scan(self):
        packets = [tcp(dport=p, t=p * 0.01) for p in (80, 443, 8080)]
        assert find_scans(packets) == []

    def test_threshold_boundary(self):
        under = [tcp(dport=p, t=p * 0.01) for p in range(1, 20)]
        exactly = [tcp(dport=p, t=p * 0.01) for p in range(1, 21)]
        assert find_scans(under, port_threshold=20) == []
        assert len(find_scans(exactly, port_threshold=20)) == 1

    def test_repeated_hits_on_one_port_are_not_a_scan(self):
        packets = [tcp(dport=443, t=i * 0.01) for i in range(500)]
        assert find_scans(packets) == []

    def test_ports_spread_across_windows_do_not_accumulate(self):
        # 15 ports in each of two windows: neither window crosses the bar.
        packets = [tcp(dport=p, t=1.0) for p in range(1, 16)]
        packets += [tcp(dport=p, t=200.0) for p in range(100, 115)]
        assert find_scans(packets, port_threshold=20) == []

    def test_one_alert_per_pair_reporting_the_worst_window(self):
        packets = [tcp(dport=p, t=1.0) for p in range(1, 60)]
        packets += [tcp(dport=p, t=200.0) for p in range(1, 30)]
        alerts = find_scans(packets)
        assert len(alerts) == 1
        assert alerts[0]["count"] == 59

    def test_separate_sources_get_separate_alerts(self):
        packets = [tcp(src="10.0.0.1", dport=p, t=p * 0.01) for p in range(1, 60)]
        packets += [tcp(src="10.0.0.2", dport=p, t=p * 0.01) for p in range(1, 60)]
        alerts = [a for a in find_scans(packets) if a["kind"] == "port_scan"]
        assert {a["source"] for a in alerts} == {"10.0.0.1", "10.0.0.2"}


class TestHostSweep:
    def test_many_hosts_on_one_port_is_a_sweep(self):
        packets = [tcp(dst=f"10.0.0.{i}", dport=445, t=i * 0.01) for i in range(1, 60)]
        sweeps = [a for a in find_scans(packets) if a["kind"] == "host_sweep"]
        assert len(sweeps) == 1
        assert sweeps[0]["count"] == 59

    def test_a_few_hosts_is_not_a_sweep(self):
        packets = [tcp(dst=f"10.0.0.{i}", dport=443, t=i) for i in range(1, 5)]
        assert find_scans(packets) == []


class TestInputHandling:
    def test_udp_is_counted(self):
        packets = []
        for port in range(1, 60):
            p = IP(src="10.0.0.66", dst="10.0.0.9") / UDP(sport=5000, dport=port)
            p.time = port * 0.01
            packets.append(p)
        assert any(a["kind"] == "port_scan" for a in find_scans(packets))

    def test_non_ip_packets_are_ignored(self):
        assert find_scans([TCP()]) == []

    def test_empty_input(self):
        assert find_scans([]) == []

    def test_alert_carries_a_readable_detail(self):
        packets = [tcp(dport=p, t=p * 0.01) for p in range(1, 60)]
        detail = find_scans(packets)[0]["detail"]
        assert "10.0.0.66" in detail and "59" in detail
