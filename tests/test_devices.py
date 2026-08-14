from scapy.all import ARP, IP, TCP, UDP, Ether

from src.model.devices import find_new_devices, observe_devices

PHONE = "4c:e6:c0:b4:56:86"
ROUTER = "aa:bb:cc:dd:ee:ff"
RANDOM = "2a:ef:82:d4:69:77"


def frame(mac, src="192.168.0.20", dst="192.168.0.1", t=0.0, payload=60):
    p = Ether(src=mac) / IP(src=src, dst=dst) / TCP(sport=5000, dport=443) / (b"x" * payload)
    p.time = t
    return p


class TestDiscovery:
    def test_finds_each_distinct_mac(self):
        packets = [frame(PHONE, t=0), frame(RANDOM, src="192.168.0.38", t=1), frame(PHONE, t=2)]
        devices = observe_devices(packets)
        assert {d["mac"] for d in devices} == {PHONE, RANDOM}

    def test_vendor_is_resolved_from_the_mac_prefix(self):
        d = observe_devices([frame(PHONE)])[0]
        assert d["vendor"] and "Apple" in d["vendor"]

    def test_randomised_macs_are_flagged(self):
        by_mac = {d["mac"]: d for d in observe_devices([frame(PHONE), frame(RANDOM)])}
        assert by_mac[RANDOM]["randomised_mac"] is True
        assert by_mac[PHONE]["randomised_mac"] is False

    def test_local_addresses_are_recorded(self):
        d = observe_devices([frame(PHONE, src="192.168.0.20")])[0]
        assert d["ips"] == ["192.168.0.20"]

    def test_public_addresses_are_not_listed_as_the_device_address(self):
        p = Ether(src=ROUTER) / IP(src="140.82.114.4", dst="192.168.0.20") / TCP()
        p.time = 0
        d = observe_devices([p])[0]
        assert d["ips"] == []
        assert d["reaches_internet"] == 1

    def test_a_forwarding_device_is_labelled_a_gateway(self):
        packets = []
        for i in range(8):
            p = Ether(src=ROUTER) / IP(src=f"140.82.114.{i}", dst="192.168.0.20") / TCP()
            p.time = i
            packets.append(p)
        packets.append(frame(PHONE, t=9))
        roles = {d["mac"]: d["role"] for d in observe_devices(packets)}
        assert roles[ROUTER] == "gateway"
        assert roles[PHONE] == "device"

    def test_arp_announcements_are_enough_to_be_seen(self):
        p = Ether(src=PHONE) / ARP(psrc="192.168.0.55", pdst="192.168.0.1")
        p.time = 0
        d = observe_devices([p])[0]
        assert d["mac"] == PHONE and d["ips"] == ["192.168.0.55"]

    def test_counts_and_timing_are_tracked(self):
        d = observe_devices([frame(PHONE, t=10), frame(PHONE, t=25)])[0]
        assert d["packets"] == 2
        assert d["first_seen"] == 0.0
        assert d["last_seen"] == 15.0

    def test_busiest_device_is_listed_first(self):
        packets = [frame(RANDOM, t=0)] + [frame(PHONE, t=i) for i in range(5)]
        assert observe_devices(packets)[0]["mac"] == PHONE

    def test_broadcast_source_is_ignored(self):
        p = Ether(src="ff:ff:ff:ff:ff:ff") / IP(src="192.168.0.9", dst="192.168.0.1") / UDP()
        p.time = 0
        assert observe_devices([p]) == []

    def test_packets_without_an_ethernet_layer_yield_nothing(self):
        p = IP(src="10.0.0.1", dst="10.0.0.2") / TCP()
        p.time = 0
        assert observe_devices([p]) == []

    def test_empty_input(self):
        assert observe_devices([]) == []


class TestNewDevices:
    def test_unknown_mac_raises_an_alert(self):
        devices = observe_devices([frame(PHONE, src="192.168.0.20")])
        alerts = find_new_devices(devices, known_macs={ROUTER})
        assert len(alerts) == 1
        assert alerts[0]["kind"] == "new_device"
        assert alerts[0]["mac"] == PHONE
        assert "192.168.0.20" in alerts[0]["detail"]

    def test_known_mac_is_silent(self):
        devices = observe_devices([frame(PHONE)])
        assert find_new_devices(devices, known_macs={PHONE}) == []

    def test_no_history_means_everything_is_new(self):
        devices = observe_devices([frame(PHONE), frame(RANDOM, src="192.168.0.38")])
        assert len(find_new_devices(devices, known_macs=set())) == 2

    def test_alert_names_the_vendor_when_there_is_one(self):
        alerts = find_new_devices(observe_devices([frame(PHONE)]), known_macs=set())
        assert "Apple" in alerts[0]["detail"]
