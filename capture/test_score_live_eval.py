"""
capture/test_score_live_eval.py: Unit tests for docs/score_live_eval.py.

Tests scoring calculations, scenario normalization, JSON output structure,
and mocked API queries without requiring a live server.
"""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from docs.score_live_eval import (
    append_result_to_json,
    fetch_flows_for_window,
    normalize_scenario_label,
    parse_args,
    score_scenario,
)


def test_normalize_scenario_label():
    """Tests scenario label mapping for different user inputs."""
    assert normalize_scenario_label("benign") == "Benign"
    assert normalize_scenario_label("Benign") == "Benign"
    assert normalize_scenario_label("portscan") == "PortScan"
    assert normalize_scenario_label("dos") == "DoS_DDoS"
    assert normalize_scenario_label("ddos") == "DoS_DDoS"
    assert normalize_scenario_label("bruteforce") == "BruteForce"
    assert normalize_scenario_label("brute_force") == "BruteForce"


def test_score_scenario_accuracy():
    """
    Tests score_scenario with a mocked list of flow records.
    """
    mock_flows = [
        {"id": 1, "label": "PortScan", "confidence": 0.99, "src_ip": "192.168.1.10"},
        {"id": 2, "label": "PortScan", "confidence": 0.95, "src_ip": "192.168.1.10"},
        {"id": 3, "label": "PortScan", "confidence": 0.97, "src_ip": "192.168.1.10"},
        {"id": 4, "label": "Benign", "confidence": 0.60, "src_ip": "192.168.1.10"},  # Mismatch
    ]

    result = score_scenario(
        flows=mock_flows,
        expected_scenario="portscan",
        start_time="2026-10-02T17:00:00Z",
        end_time="2026-10-02T17:05:00Z",
    )

    assert result["total_flows"] == 4
    assert result["correct_predictions"] == 3
    assert result["incorrect_predictions"] == 1
    assert result["accuracy_pct"] == 75.0
    assert result["expected_label"] == "PortScan"
    assert result["label_distribution"]["PortScan"] == 3
    assert result["label_distribution"]["Benign"] == 1
    assert "timestamp_evaluated" in result


def test_score_scenario_empty_flows():
    """Tests score_scenario when no flows are present in window."""
    result = score_scenario(
        flows=[],
        expected_scenario="dos",
        start_time="2026-10-02T17:00:00Z",
        end_time="2026-10-02T17:05:00Z",
    )
    assert result["total_flows"] == 0
    assert result["correct_predictions"] == 0
    assert result["incorrect_predictions"] == 0
    assert result["accuracy_pct"] == 0.0


def test_append_result_to_json_accumulates():
    """
    Tests that append_result_to_json correctly appends successive runs to a JSON list.
    """
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
        tmp_json = f.name

    try:
        run1 = {
            "start_time": "2026-10-02T17:00:00Z",
            "end_time": "2026-10-02T17:05:00Z",
            "expected_scenario": "benign",
            "accuracy_pct": 100.0,
        }
        run2 = {
            "start_time": "2026-10-02T17:05:00Z",
            "end_time": "2026-10-02T17:10:00Z",
            "expected_scenario": "dos",
            "accuracy_pct": 98.5,
        }

        append_result_to_json(run1, output_path=tmp_json)
        append_result_to_json(run2, output_path=tmp_json)

        with open(tmp_json, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert isinstance(data, list)
        assert len(data) == 2
        assert data[0]["expected_scenario"] == "benign"
        assert data[1]["expected_scenario"] == "dos"
    finally:
        Path(tmp_json).unlink(missing_ok=True)


def test_fetch_flows_for_window_mocked():
    """
    Tests fetch_flows_for_window with pagination against a mocked HTTP client.
    """
    mock_client = MagicMock()
    
    # Simulate page 1 with 2 items (total=3), page 2 with 1 item
    mock_resp_1 = MagicMock(status_code=200)
    mock_resp_1.json.return_value = {
        "total": 3,
        "limit": 2,
        "offset": 0,
        "flows": [{"id": 1, "label": "Benign"}, {"id": 2, "label": "Benign"}],
    }

    mock_resp_2 = MagicMock(status_code=200)
    mock_resp_2.json.return_value = {
        "total": 3,
        "limit": 2,
        "offset": 2,
        "flows": [{"id": 3, "label": "Benign"}],
    }

    mock_client.get.side_effect = [mock_resp_1, mock_resp_2]

    flows = fetch_flows_for_window(
        start_time="2026-10-02T17:00:00Z",
        end_time="2026-10-02T17:05:00Z",
        client=mock_client,
    )

    assert len(flows) == 3
    assert flows[0]["id"] == 1
    assert flows[2]["id"] == 3
    assert mock_client.get.call_count == 2


def test_parse_args_scoring():
    """Tests CLI argument parsing for score_live_eval."""
    args = parse_args([
        "--start", "2026-10-02T17:00:00",
        "--end", "2026-10-02T17:05:00",
        "--expected", "dos",
        "--api-url", "http://127.0.0.1:8000",
    ])
    assert args.start == "2026-10-02T17:00:00"
    assert args.end == "2026-10-02T17:05:00"
    assert args.expected == "dos"
    assert args.api_url == "http://127.0.0.1:8000"
    assert args.output == "docs/live_eval_results.json"
