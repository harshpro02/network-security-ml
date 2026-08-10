"""Flow grouping and expiry.

These are the rules that have to match CICFlowMeter, which built the
CICIDS2017 rows the model was trained on. If they drift, the features
computed live stop meaning what they meant in training.
"""
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
        # 121s after the first packet, so a new flow must start.
        flows = flows_from([packet(t=0), packet(t=121)])
        assert len(flows) == 2
        assert all(len(packets) == 1 for _, packets in flows)

    def test_timeout_is_measured_from_flow_start_not_last_packet(self):
        # Steady traffic every 100s: gaps are under the timeout, but the
        # flow's own age crosses it, so it still has to roll over.
        flows = flows_from([packet(t=0), packet(t=100), packet(t=200)])
        assert len(flows) == 2

    def test_fin_closes_the_flow(self):
        flows = flows_from([packet(t=0), packet(t=1, flags="FA"), packet(t=2)])
        assert len(flows) == 2
        assert len(flows[0][1]) == 2   # up to and including the FIN

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

    def test_average_uses_full_frame_length(self):
        # 100 bytes of payload plus IP and TCP headers, not just the payload.
        _, _, total, _ = flow_to_features([packet(payload=100)])
        assert total > 100
