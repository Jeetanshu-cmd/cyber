"""
capture/test_flow_table.py: Unit tests for Flow and FlowTable.

Tests flow aggregation, canonical 5-tuple keying, bidirectional mapping,
and expiration triggers (FIN/RST flag, idle timeout, active timeout)
against synthetic packet sequences without requiring live network interfaces or Scapy.
"""

import pytest
from capture.flow_table import Flow, FlowTable, canonical_flow_key


def create_normal_exchange_packets():
    """
    Sequence (a): Normal HTTP exchange (Initiator <-> Web Server)
    Includes 3-way handshake, data exchange, and FIN teardown.
    """
    return [
        {
            "timestamp": 100.00,
            "src_ip": "192.168.1.50",
            "src_port": 54321,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
            "size": 64,
            "tcp_flags": {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False},
        },
        {
            "timestamp": 100.02,
            "src_ip": "10.0.0.1",
            "src_port": 80,
            "dst_ip": "192.168.1.50",
            "dst_port": 54321,
            "protocol": "TCP",
            "size": 64,
            "tcp_flags": {"SYN": True, "ACK": True, "FIN": False, "RST": False, "PSH": False},
        },
        {
            "timestamp": 100.03,
            "src_ip": "192.168.1.50",
            "src_port": 54321,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
            "size": 54,
            "tcp_flags": {"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False},
        },
        {
            "timestamp": 100.10,
            "src_ip": "192.168.1.50",
            "src_port": 54321,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
            "size": 512,
            "tcp_flags": {"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": True},
        },
        {
            "timestamp": 100.20,
            "src_ip": "10.0.0.1",
            "src_port": 80,
            "dst_ip": "192.168.1.50",
            "dst_port": 54321,
            "protocol": "TCP",
            "size": 1400,
            "tcp_flags": {"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": True},
        },
        {
            "timestamp": 100.30,
            "src_ip": "192.168.1.50",
            "src_port": 54321,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
            "size": 54,
            "tcp_flags": {"SYN": False, "ACK": True, "FIN": True, "RST": False, "PSH": False},
        },
    ]


def create_syn_flood_packets(n: int = 50):
    """
    Sequence (b): SYN-flood attack sequence
    High frequency of SYN packets to a single target from a fixed attacker port.
    """
    packets = []
    for i in range(n):
        packets.append({
            "timestamp": 200.0 + (i * 0.001),  # 1ms IAT
            "src_ip": "192.168.1.99",
            "src_port": 40000,
            "dst_ip": "10.0.0.1",
            "dst_port": 80,
            "protocol": "TCP",
            "size": 60,
            "tcp_flags": {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False},
        })
    return packets


def create_port_scan_packets(ports_count: int = 15):
    """
    Sequence (c): Port-scan sequence
    Single SYN packet sent across multiple distinct destination ports from the same source IP.
    """
    packets = []
    for i in range(ports_count):
        packets.append({
            "timestamp": 300.0 + (i * 0.05),
            "src_ip": "192.168.1.77",
            "src_port": 50000 + i,
            "dst_ip": "10.0.0.1",
            "dst_port": 1000 + i,  # Distinct ports
            "protocol": "TCP",
            "size": 44,
            "tcp_flags": {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False},
        })
    return packets


def test_canonical_flow_key_symmetry():
    """Verifies that reverse directions generate identical canonical keys."""
    key1 = canonical_flow_key("192.168.1.5", 1234, "10.0.0.1", 80, "TCP")
    key2 = canonical_flow_key("10.0.0.1", 80, "192.168.1.5", 1234, "tcp")
    assert key1 == key2


def test_normal_exchange_flow_aggregation():
    """
    Tests that bidirectional packets in sequence (a) aggregate into exactly 1 Flow.
    """
    table = FlowTable()
    packets = create_normal_exchange_packets()

    for p in packets:
        table.add_packet(p)

    assert len(table) == 1
    flow = list(table.flows.values())[0]

    assert flow.fwd_src_ip == "192.168.1.50"
    assert flow.fwd_dst_port == 80
    assert len(flow.packets) == 6
    assert flow.has_fin_or_rst is True

    # Count forward vs backward
    fwd_count = sum(1 for p in flow.packets if p["direction"] == "fwd")
    bwd_count = sum(1 for p in flow.packets if p["direction"] == "bwd")
    assert fwd_count == 4
    assert bwd_count == 2


def test_port_scan_separate_flows():
    """
    Tests sequence (c): Ensure port scan creates separate distinct flows per dst_port.
    """
    table = FlowTable()
    packets = create_port_scan_packets(ports_count=10)

    for p in packets:
        table.add_packet(p)

    assert len(table) == 10
    dst_ports = {f.fwd_dst_port for f in table.flows.values()}
    assert len(dst_ports) == 10


def test_expiration_on_fin_flag():
    """Tests that flow containing FIN expires immediately upon check."""
    table = FlowTable(idle_timeout=5.0, active_timeout=30.0)
    packets = create_normal_exchange_packets()

    for p in packets:
        table.add_packet(p)

    # Calling expire_flows at time 100.35 (shortly after last packet)
    expired = table.expire_flows(now=100.35)
    assert len(expired) == 1
    assert len(table) == 0
    assert expired[0].has_fin_or_rst is True


def test_expiration_on_idle_timeout():
    """Tests that an inactive flow expires after idle_timeout elapsed."""
    table = FlowTable(idle_timeout=5.0, active_timeout=30.0)

    p1 = {
        "timestamp": 10.0,
        "src_ip": "10.0.0.2",
        "src_port": 1111,
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "protocol": "TCP",
        "size": 60,
        "tcp_flags": {"SYN": True, "ACK": False, "FIN": False, "RST": False, "PSH": False},
    }
    table.add_packet(p1)

    # At t=12.0 (2s idle), should NOT expire (idle_timeout is 5s)
    expired_early = table.expire_flows(now=12.0)
    assert len(expired_early) == 0
    assert len(table) == 1

    # At t=16.0 (6s idle), SHOULD expire
    expired_late = table.expire_flows(now=16.0)
    assert len(expired_late) == 1
    assert len(table) == 0


def test_expiration_on_active_timeout():
    """Tests that a long-running active flow expires after active_timeout."""
    table = FlowTable(idle_timeout=10.0, active_timeout=20.0)

    # Add packets continuously so it never idles out
    for sec in range(0, 25, 2):
        table.add_packet({
            "timestamp": float(sec),
            "src_ip": "10.0.0.5",
            "src_port": 2222,
            "dst_ip": "10.0.0.1",
            "dst_port": 443,
            "protocol": "TCP",
            "size": 100,
            "tcp_flags": {"SYN": False, "ACK": True, "FIN": False, "RST": False, "PSH": False},
        })

    # At t=24.0, total duration is 24s > 20s active_timeout
    expired = table.expire_flows(now=24.0)
    assert len(expired) == 1
    assert len(table) == 0


def test_packet_to_dict_conversion():
    """Tests packet_to_dict with dict pass-through and mock packets."""
    from capture.sniffer import packet_to_dict

    dict_pkt = {
        "timestamp": 123.45,
        "src_ip": "192.168.1.1",
        "dst_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_port": 80,
        "protocol": "TCP",
        "size": 60,
    }
    assert packet_to_dict(dict_pkt) == dict_pkt
    assert packet_to_dict("invalid_non_packet") is None


def test_flow_client_buffering_and_recovery():
    """
    Tests FlowClient queue buffering on HTTP failure and subsequent flush on recovery.
    """
    from unittest.mock import MagicMock
    from capture.client import FlowClient

    client = FlowClient(api_url="http://localhost:8000", max_buffer_size=10)
    
    # Mock _post_payload to fail initially
    client._post_payload = MagicMock(return_value=False)

    dummy_features = {"dst_port": 80.0}
    success = client.send_flow("192.168.1.10", "10.0.0.1", 80, dummy_features)

    assert success is False
    assert len(client.buffer) == 1
    assert client.buffer[0]["src_ip"] == "192.168.1.10"

    # Now mock recovery
    client._post_payload = MagicMock(return_value=True)
    flushed = client.flush_buffer()

    assert flushed == 1
    assert len(client.buffer) == 0

