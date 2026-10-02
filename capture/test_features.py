"""
capture/test_features.py: Unit tests for 19-feature extraction contract.

Verifies feature calculations, key names, exact contract ordering matching
ml/artifacts/features.json, and safe handling of zero-duration / single-packet flows.
"""

import json
from pathlib import Path

import pytest
from capture.features import FEATURE_KEYS, compute_features
from capture.flow_table import FlowTable
from capture.test_flow_table import (
    create_normal_exchange_packets,
    create_port_scan_packets,
    create_syn_flood_packets,
)


def test_feature_keys_match_ml_contract_artifact():
    """
    Asserts that FEATURE_KEYS in capture/features.py perfectly match
    ml/artifacts/features.json in both key names and strict sequence order.
    """
    artifact_path = Path("ml/artifacts/features.json")
    assert artifact_path.exists(), "ml/artifacts/features.json not found"

    with open(artifact_path, "r") as f:
        spec = json.load(f)

    expected_features = spec["features"]
    assert len(FEATURE_KEYS) == 19
    assert FEATURE_KEYS == expected_features


def test_compute_features_normal_exchange():
    """
    Tests feature extraction on Sequence (a): normal HTTP exchange.
    """
    table = FlowTable()
    for p in create_normal_exchange_packets():
        table.add_packet(p)

    flow = list(table.flows.values())[0]
    features = compute_features(flow)

    # Verify keys and order
    assert list(features.keys()) == FEATURE_KEYS

    # Verify values
    assert features["dst_port"] == 80.0
    assert pytest.approx(features["flow_duration_s"], abs=1e-3) == 0.30
    assert features["fwd_packets"] == 4.0
    assert features["bwd_packets"] == 2.0
    assert features["fwd_bytes"] == 64 + 54 + 512 + 54  # 684.0
    assert features["bwd_bytes"] == 64 + 1400  # 1464.0
    assert features["syn_count"] == 2.0
    assert features["ack_count"] == 5.0
    assert features["fin_count"] == 1.0
    assert features["rst_count"] == 0.0
    assert features["psh_count"] == 2.0

    # Rates
    assert features["bytes_per_sec"] > 0.0
    assert features["packets_per_sec"] > 0.0

    # Length stats
    assert features["pkt_len_min"] == 54.0
    assert features["pkt_len_max"] == 1400.0
    assert features["pkt_len_mean"] > 0.0
    assert features["pkt_len_std"] > 0.0

    # IATs
    assert features["iat_mean"] > 0.0
    assert features["iat_max"] > 0.0


def test_compute_features_syn_flood():
    """
    Tests feature extraction on Sequence (b): SYN flood attack sequence.
    """
    table = FlowTable()
    flood_packets = create_syn_flood_packets(n=50)
    for p in flood_packets:
        table.add_packet(p)

    flow = list(table.flows.values())[0]
    features = compute_features(flow)

    assert features["dst_port"] == 80.0
    assert features["fwd_packets"] == 50.0
    assert features["bwd_packets"] == 0.0
    assert features["syn_count"] == 50.0
    assert features["ack_count"] == 0.0
    assert features["fin_count"] == 0.0

    # High packet rate and very short IAT
    assert features["packets_per_sec"] > 500.0
    assert pytest.approx(features["iat_mean"], abs=1e-4) == 0.001
    assert pytest.approx(features["iat_max"], abs=1e-4) == 0.001


def test_compute_features_single_packet_flow():
    """
    Tests Sequence (c) single-packet flow: zero-duration edge case.
    Rates, std, and IATs must be safely 0.0 without NaN or divide-by-zero errors.
    """
    table = FlowTable()
    port_scan_packets = create_port_scan_packets(ports_count=1)
    for p in port_scan_packets:
        table.add_packet(p)

    flow = list(table.flows.values())[0]
    features = compute_features(flow)

    assert features["dst_port"] == 1000.0
    assert features["flow_duration_s"] == 0.0
    assert features["fwd_packets"] == 1.0
    assert features["bwd_packets"] == 0.0
    assert features["bytes_per_sec"] == 0.0
    assert features["packets_per_sec"] == 0.0
    assert features["pkt_len_mean"] == 44.0
    assert features["pkt_len_std"] == 0.0
    assert features["pkt_len_max"] == 44.0
    assert features["pkt_len_min"] == 44.0
    assert features["syn_count"] == 1.0
    assert features["ack_count"] == 0.0
    assert features["iat_mean"] == 0.0
    assert features["iat_max"] == 0.0

    # Ensure no NaN or Inf in output dictionary
    for k, v in features.items():
        assert isinstance(v, float)
        assert not (v != v), f"Feature '{k}' returned NaN"
        assert abs(v) != float("inf"), f"Feature '{k}' returned Inf"
