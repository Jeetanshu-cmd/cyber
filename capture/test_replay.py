"""
capture/test_replay.py: Unit tests for capture/replay.py.

Tests CSV-reading, row-shaping, ground_truth_label stripping, retry logic,
and accuracy evaluation using a fixture CSV and mocked HTTP endpoints.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import httpx
import pandas as pd
import pytest

from capture.replay import (
    generate_plausible_ips,
    parse_args,
    prepare_flow_payload,
    replay_flows,
    send_flow,
)


@pytest.fixture
def sample_csv_data():
    """
    Creates a small DataFrame fixture mimicking held_out_sample.csv.
    """
    return [
        {
            "dst_port": 80.0,
            "flow_duration_s": 0.05,
            "fwd_packets": 2.0,
            "bwd_packets": 2.0,
            "fwd_bytes": 100.0,
            "bwd_bytes": 200.0,
            "bytes_per_sec": 6000.0,
            "packets_per_sec": 80.0,
            "pkt_len_mean": 75.0,
            "pkt_len_std": 25.0,
            "pkt_len_max": 150.0,
            "pkt_len_min": 50.0,
            "syn_count": 1.0,
            "ack_count": 1.0,
            "fin_count": 0.0,
            "rst_count": 0.0,
            "psh_count": 0.0,
            "iat_mean": 0.01,
            "iat_max": 0.02,
            "ground_truth_label": "Benign",
        },
        {
            "dst_port": 22.0,
            "flow_duration_s": 1.5,
            "fwd_packets": 10.0,
            "bwd_packets": 8.0,
            "fwd_bytes": 500.0,
            "bwd_bytes": 400.0,
            "bytes_per_sec": 600.0,
            "packets_per_sec": 12.0,
            "pkt_len_mean": 50.0,
            "pkt_len_std": 10.0,
            "pkt_len_max": 80.0,
            "pkt_len_min": 20.0,
            "syn_count": 2.0,
            "ack_count": 2.0,
            "fin_count": 1.0,
            "rst_count": 0.0,
            "psh_count": 1.0,
            "iat_mean": 0.1,
            "iat_max": 0.2,
            "ground_truth_label": "BruteForce",
        },
        {
            "dst_port": 443.0,
            "flow_duration_s": 0.001,
            "fwd_packets": 1.0,
            "bwd_packets": 0.0,
            "fwd_bytes": 50.0,
            "bwd_bytes": 0.0,
            "bytes_per_sec": 50000.0,
            "packets_per_sec": 1000.0,
            "pkt_len_mean": 50.0,
            "pkt_len_std": 0.0,
            "pkt_len_max": 50.0,
            "pkt_len_min": 50.0,
            "syn_count": 1.0,
            "ack_count": 0.0,
            "fin_count": 0.0,
            "rst_count": 0.0,
            "psh_count": 0.0,
            "iat_mean": 0.0,
            "iat_max": 0.0,
            "ground_truth_label": "PortScan",
        },
        {
            "dst_port": 8080.0,
            "flow_duration_s": 5.0,
            "fwd_packets": 100.0,
            "bwd_packets": 0.0,
            "fwd_bytes": 10000.0,
            "bwd_bytes": 0.0,
            "bytes_per_sec": 2000.0,
            "packets_per_sec": 20.0,
            "pkt_len_mean": 100.0,
            "pkt_len_std": 0.0,
            "pkt_len_max": 100.0,
            "pkt_len_min": 100.0,
            "syn_count": 100.0,
            "ack_count": 0.0,
            "fin_count": 0.0,
            "rst_count": 0.0,
            "psh_count": 0.0,
            "iat_mean": 0.05,
            "iat_max": 0.05,
            "ground_truth_label": "DoS_DDoS",
        },
    ]


@pytest.fixture
def temp_csv_file(sample_csv_data):
    """
    Creates a temporary CSV file with fixture rows.
    """
    df = pd.DataFrame(sample_csv_data)
    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
        csv_path = f.name
        df.to_csv(csv_path, index=False)

    yield csv_path

    Path(csv_path).unlink(missing_ok=True)


def test_prepare_flow_payload_strips_ground_truth(sample_csv_data):
    """
    Ensures that prepare_flow_payload removes 'ground_truth_label' from the features dict
    and keeps it as the returned metadata label.
    """
    row = sample_csv_data[0]
    payload, ground_truth = prepare_flow_payload(row, src_ip="192.168.1.10", dst_ip="10.0.0.1")

    assert ground_truth == "Benign"
    assert "src_ip" in payload
    assert payload["src_ip"] == "192.168.1.10"
    assert payload["dst_ip"] == "10.0.0.1"
    assert payload["dst_port"] == 80
    assert "ground_truth_label" not in payload
    assert "ground_truth_label" not in payload["features"]
    assert "Label" not in payload["features"]
    assert payload["features"]["dst_port"] == 80.0
    assert payload["features"]["flow_duration_s"] == 0.05
    assert len(payload["features"]) == 19


def test_generate_plausible_ips():
    """
    Tests random IP generation for valid private address patterns.
    """
    src_ip, dst_ip = generate_plausible_ips()
    assert src_ip.startswith(("192.168.1.", "10.0.0.", "172.16.0."))
    assert dst_ip.startswith(("192.168.1.", "10.0.0.", "172.16.0."))


def test_send_flow_success():
    """
    Tests sending a flow payload when the API returns 200 OK.
    """
    mock_client = MagicMock()
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {
        "id": 1,
        "label": "Benign",
        "confidence": 0.99,
        "top_features": [],
    }
    mock_client.post.return_value = mock_response

    payload = {
        "src_ip": "192.168.1.5",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "features": {"dst_port": 80.0},
    }

    result = send_flow("http://localhost:8000", payload, client=mock_client)
    assert result is not None
    assert result["label"] == "Benign"
    mock_client.post.assert_called_once_with(
        "http://localhost:8000/ingest/flows", json=payload
    )


def test_send_flow_retry_and_recovery():
    """
    Tests retry behavior: fails once on network error, then succeeds on retry.
    """
    mock_client = MagicMock()
    mock_success = MagicMock()
    mock_success.status_code = 200
    mock_success.json.return_value = {
        "id": 2,
        "label": "DoS_DDoS",
        "confidence": 0.95,
        "top_features": [],
    }

    # First attempt raises RequestError, second attempt succeeds
    mock_client.post.side_effect = [
        httpx.RequestError("Connection reset"),
        mock_success,
    ]

    payload = {
        "src_ip": "192.168.1.5",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "features": {"dst_port": 80.0},
    }

    result = send_flow("http://localhost:8000", payload, client=mock_client, max_retries=1)
    assert result is not None
    assert result["label"] == "DoS_DDoS"
    assert mock_client.post.call_count == 2


def test_send_flow_repeated_failure_skips_without_crashing():
    """
    Tests that repeatedly failing requests are logged and skipped (returning None).
    """
    mock_client = MagicMock()
    mock_client.post.side_effect = httpx.RequestError("Connection refused")

    payload = {
        "src_ip": "192.168.1.5",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "features": {"dst_port": 80.0},
    }

    result = send_flow("http://localhost:8000", payload, client=mock_client, max_retries=1)
    assert result is None
    assert mock_client.post.call_count == 2


def test_replay_flows_end_to_end_mocked(temp_csv_file):
    """
    Tests replay_flows loop against a temporary fixture CSV, verifying
    accurate tracking of running accuracy, payload formatting, and ground truth preservation.
    """
    mock_client = MagicMock()

    # Define mock return values matching 3 out of 4 correct predictions
    mock_responses = [
        MagicMock(status_code=200, json=lambda: {"id": 1, "label": "Benign", "confidence": 0.99}),
        MagicMock(status_code=200, json=lambda: {"id": 2, "label": "BruteForce", "confidence": 0.95}),
        MagicMock(status_code=200, json=lambda: {"id": 3, "label": "PortScan", "confidence": 0.98}),
        MagicMock(status_code=200, json=lambda: {"id": 4, "label": "Benign", "confidence": 0.60}),  # Mismatch (ground truth is DoS_DDoS)
    ]
    mock_client.post.side_effect = mock_responses

    stats = replay_flows(
        csv_path=temp_csv_file,
        rate=0.0,  # 0 rate for instant test execution
        api_url="http://localhost:8000",
        client=mock_client,
    )

    assert stats["total_rows"] == 4
    assert stats["sent"] == 4
    assert stats["failed"] == 0
    assert stats["evaluated"] == 4
    assert stats["correct"] == 3
    assert stats["accuracy"] == 75.0  # 3/4 = 75%

    # Verify that the sent payloads NEVER contained ground_truth_label
    for call in mock_client.post.call_args_list:
        sent_json = call.kwargs["json"]
        assert "ground_truth_label" not in sent_json
        assert "ground_truth_label" not in sent_json["features"]
        assert "src_ip" in sent_json
        assert "dst_ip" in sent_json
        assert "dst_port" in sent_json
        assert isinstance(sent_json["features"], dict)


def test_parse_args_defaults():
    """
    Tests default CLI argument parsing.
    """
    args = parse_args([])
    assert args.csv == "ml/artifacts/held_out_sample.csv"
    assert args.rate == 5.0
    assert args.api_url == "http://localhost:8000"


def test_parse_args_custom():
    """
    Tests custom CLI argument parsing.
    """
    args = parse_args(["--csv", "custom.csv", "--rate", "10.5", "--api-url", "http://127.0.0.1:9000"])
    assert args.csv == "custom.csv"
    assert args.rate == 10.5
    assert args.api_url == "http://127.0.0.1:9000"
