from scapy.all import IP, TCP, UDP

from src.model.behaviour import find_beacons, find_scans


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


def flow(src="10.0.0.5", dst="93.184.216.34", dport=443, t=0.0, n=3):
    packets = []
    for i in range(n):
        p = IP(src=src, dst=dst) / TCP(sport=50000, dport=dport)
        p.time = t + i * 0.01
        packets.append(p)
    return ((src, dst, 50000, dport, 6), packets)


class TestBeaconing:
    def test_perfectly_regular_calls_home_are_flagged(self):
        flows = [flow(t=i * 60.0) for i in range(10)]
        alerts = find_beacons(flows)
        assert len(alerts) == 1
        assert alerts[0]["kind"] == "beacon"
        assert alerts[0]["interval_seconds"] == 60.0
        assert alerts[0]["count"] == 10

    def test_small_jitter_still_counts(self):
        offsets = [0, 60.5, 119.4, 180.6, 240.2, 299.5, 360.8]
        alerts = find_beacons([flow(t=o) for o in offsets])
        assert len(alerts) == 1

    def test_irregular_browsing_is_not_a_beacon(self):
        offsets = [0, 3, 47, 51, 52, 300, 301, 900]
        assert find_beacons([flow(t=o) for o in offsets]) == []

    def test_too_few_connections_is_not_a_beacon(self):
        assert find_beacons([flow(t=i * 60.0) for i in range(5)]) == []

    def test_rapid_bursts_are_not_beacons(self):
        # Ten connections a tenth of a second apart is a page loading,
        # not something calling home.
        assert find_beacons([flow(t=i * 0.1) for i in range(10)]) == []

    def test_separate_destinations_are_judged_separately(self):
        flows = [flow(dst="1.1.1.1", t=i * 60.0) for i in range(8)]
        flows += [flow(dst="2.2.2.2", t=o) for o in (0, 5, 90, 700, 701, 1500)]
        alerts = find_beacons(flows)
        assert [a["target"] for a in alerts] == ["1.1.1.1"]

    def test_same_host_different_ports_are_separate(self):
        flows = [flow(dport=443, t=i * 60.0) for i in range(8)]
        flows += [flow(dport=80, t=i * 60.0) for i in range(8)]
        assert {a["port"] for a in find_beacons(flows)} == {80, 443}

    def test_jitter_is_reported(self):
        alert = find_beacons([flow(t=i * 30.0) for i in range(8)])[0]
        assert alert["jitter"] == 0.0

    def test_detail_is_readable(self):
        detail = find_beacons([flow(t=i * 60.0) for i in range(8)])[0]["detail"]
        assert "93.184.216.34:443" in detail and "8 times" in detail

    def test_empty_input(self):
        assert find_beacons([]) == []
