import pytest
from scapy.all import IP, TCP, UDP

from src.model.live_bridge import FlowTable, flow_to_features, get_flow_key


def packet(src="10.0.0.1", dst="10.0.0.2", sport=1234, dport=80,
           t=0.0, payload=100, flags="A"):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags) / (b"x" * payload)
    p.time = t
    return p


def flows_from(packets):
    table = FlowTable()
    for p in packets:
        table.add(p)
    return table.finish()


class TestFlowKey:
    def test_same_conversation_shares_a_key(self):
        assert get_flow_key(packet(t=0)) == get_flow_key(packet(t=5))

    def test_direction_matters(self):
        fwd = get_flow_key(packet(src="10.0.0.1", dst="10.0.0.2"))
        bwd = get_flow_key(packet(src="10.0.0.2", dst="10.0.0.1"))
        assert fwd != bwd

    def test_ports_are_part_of_the_key(self):
        assert get_flow_key(packet(sport=1111)) != get_flow_key(packet(sport=2222))

    def test_non_ip_packets_are_ignored(self):
        assert get_flow_key(TCP()) is None

    def test_udp_ports_are_read(self):
        p = IP(src="10.0.0.1", dst="10.0.0.2") / UDP(sport=53, dport=9999)
        assert get_flow_key(p) == ("10.0.0.1", "10.0.0.2", 53, 9999, 17)


class TestExpiry:
    def test_packets_within_the_timeout_stay_one_flow(self):
        flows = flows_from([packet(t=0), packet(t=60), packet(t=119)])
        assert len(flows) == 1
        assert len(flows[0][1]) == 3

    def test_flow_splits_once_past_the_timeout(self):
        flows = flows_from([packet(t=0), packet(t=121)])
        assert len(flows) == 2
        assert all(len(packets) == 1 for _, packets in flows)

    def test_timeout_is_measured_from_flow_start_not_last_packet(self):
        flows = flows_from([packet(t=0), packet(t=100), packet(t=200)])
        assert len(flows) == 2

    def test_fin_closes_the_flow(self):
        flows = flows_from([packet(t=0), packet(t=1, flags="FA"), packet(t=2)])
        assert len(flows) == 2
        assert len(flows[0][1]) == 2

    def test_rst_closes_the_flow(self):
        flows = flows_from([packet(t=0), packet(t=1, flags="R"), packet(t=2)])
        assert len(flows) == 2

    def test_separate_conversations_do_not_merge(self):
        flows = flows_from([packet(sport=1111, t=0), packet(sport=2222, t=0)])
        assert len(flows) == 2

    def test_finish_drains_the_table(self):
        table = FlowTable()
        table.add(packet(t=0))
        assert len(table.finish()) == 1
        assert table.finish() == []

    def test_tables_are_independent(self):
        a, b = FlowTable(), FlowTable()
        a.add(packet(sport=1111))
        b.add(packet(sport=2222))
        assert len(a.finish()) == 1
        assert len(b.finish()) == 1

    def test_packets_seen_counts_everything_offered(self):
        table = FlowTable()
        table.add(packet())
        table.add(TCP())
        assert table.packets_seen == 2


class TestFeatures:
    def test_duration_spans_first_to_last_packet(self):
        duration, count, total, avg = flow_to_features(
            [packet(t=10, payload=100), packet(t=13.5, payload=100)])
        assert duration == pytest.approx(3.5)
        assert count == 2

    def test_single_packet_flow_has_zero_duration(self):
        duration, count, _, _ = flow_to_features([packet(t=7)])
        assert duration == 0
        assert count == 1

    def test_totals_and_average_agree(self):
        _, count, total, avg = flow_to_features([packet(payload=100), packet(payload=200)])
        assert total == pytest.approx(count * avg)

    def test_size_counts_payload_not_frame(self):
        _, _, total, _ = flow_to_features([packet(payload=100)])
        assert total == 100

    def test_bare_syn_counts_as_zero_bytes(self):
        _, _, total, avg = flow_to_features([packet(payload=0, flags="S")])
        assert total == 0
        assert avg == 0


def reply(src="10.0.0.2", dst="10.0.0.1", sport=80, dport=1234, t=0.0, payload=100, flags="A"):
    return packet(src=src, dst=dst, sport=sport, dport=dport, t=t, payload=payload, flags=flags)


class TestBidirectional:
    def test_both_directions_land_in_one_flow(self):
        flows = flows_from([packet(t=0), reply(t=1), packet(t=2)])
        assert len(flows) == 1
        assert len(flows[0][1]) == 3

    def test_the_opener_defines_the_flow_direction(self):
        key, _ = flows_from([packet(t=0), reply(t=1)])[0]
        assert key[0] == "10.0.0.1" and key[2] == 1234
        assert key[1] == "10.0.0.2" and key[3] == 80

    def test_a_reply_first_capture_is_keyed_on_the_reply(self):
        key, _ = flows_from([reply(t=0), packet(t=1)])[0]
        assert key[0] == "10.0.0.2" and key[2] == 80

    def test_fwd_columns_count_only_the_opening_direction(self):
        key, packets = flows_from(
            [packet(t=0, payload=100), reply(t=1, payload=500), packet(t=2, payload=100)])[0]
        duration, count, total, avg = flow_to_features(packets, key)
        assert count == 2
        assert total == 200

    def test_average_packet_size_spans_both_directions(self):
        key, packets = flows_from([packet(t=0, payload=100), reply(t=1, payload=200)])[0]
        _, _, total, avg = flow_to_features(packets, key)
        assert total == 100
        assert avg == 150

    def test_duration_spans_the_whole_conversation(self):
        key, packets = flows_from([packet(t=0), reply(t=9)])[0]
        duration, _, _, _ = flow_to_features(packets, key)
        assert duration == pytest.approx(9)

    def test_without_a_key_every_packet_counts_as_forward(self):
        _, count, _, _ = flow_to_features([packet(t=0), reply(t=1)])
        assert count == 2

    def test_separate_conversations_still_separate(self):
        flows = flows_from([packet(sport=1111, t=0), packet(sport=2222, t=0)])
        assert len(flows) == 2
