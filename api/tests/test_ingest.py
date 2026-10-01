"""
api/tests/test_ingest.py: Unit and integration tests for flow ingestion, DB persistence, WebSocket broadcasts, and alert de-duplication.
"""

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from api.main import app
from api.alerts import alert_tracker
from api.db import init_db

# Ensure DB tables are created before running tests
init_db()

client = TestClient(app)

def get_sample_features():
    held_out_df = pd.read_csv("ml/artifacts/held_out_sample.csv")
    sample_row = held_out_df.iloc[0].to_dict()
    sample_row.pop("ground_truth_label")
    return sample_row

def test_ingest_flow_endpoint():
    features = get_sample_features()
    payload = {
        "src_ip": "192.168.1.50",
        "dst_ip": "10.0.0.1",
        "dst_port": 80,
        "features": features
    }

    response = client.post("/ingest/flows", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "id" in data
    assert "label" in data
    assert "confidence" in data
    assert "top_features" in data
    flow_id = data["id"]

    # Verify persistence via GET /flows/{id}
    get_resp = client.get(f"/flows/{flow_id}")
    assert get_resp.status_code == 200
    stored_flow = get_resp.json()
    assert stored_flow["id"] == flow_id
    assert stored_flow["src_ip"] == "192.168.1.50"
    assert stored_flow["dst_ip"] == "10.0.0.1"
    assert stored_flow["dst_port"] == 80
    assert isinstance(stored_flow["features"], dict)
    assert isinstance(stored_flow["top_features"], list)

def test_flows_pagination_and_filtering():
    get_resp = client.get("/flows?limit=10")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert "total" in data
    assert "flows" in data
    assert len(data["flows"]) <= 10

def test_system_stats_endpoint():
    get_resp = client.get("/stats?minutes=60")
    assert get_resp.status_code == 200
    data = get_resp.json()
    assert "time_window_minutes" in data
    assert "counts_by_label" in data
    assert data["time_window_minutes"] == 60

def test_websocket_broadcast_and_alert_dedup():
    alert_tracker.reset()
    features = get_sample_features()

    # Find an attack row in held_out_sample.csv to trigger an alert
    held_out_df = pd.read_csv("ml/artifacts/held_out_sample.csv")
    attack_row = None
    for _, row in held_out_df.iterrows():
        row_dict = row.to_dict()
        label = row_dict.pop("ground_truth_label")
        if label in ["DoS_DDoS", "PortScan", "BruteForce"]:
            attack_row = row_dict
            break

    if not attack_row:
        attack_row = features

    payload = {
        "src_ip": "192.168.1.99",
        "dst_ip": "10.0.0.5",
        "dst_port": 80,
        "features": attack_row
    }

    with client.websocket_connect("/ws/flows") as websocket:
        # First ingest call -> fires flow event + alert event
        resp1 = client.post("/ingest/flows", json=payload)
        assert resp1.status_code == 200
        flow_id_1 = resp1.json()["id"]

        event1 = websocket.receive_json()
        assert event1["type"] == "flow"
        assert event1["data"]["id"] == flow_id_1

        event2 = websocket.receive_json()
        assert event2["type"] == "alert"
        assert event2["data"]["src_ip"] == "192.168.1.99"
        assert event2["data"]["flow_id"] == flow_id_1

        # Second immediate ingest call from same src_ip & label -> flow event fires, but alert de-dups
        resp2 = client.post("/ingest/flows", json=payload)
        assert resp2.status_code == 200
        flow_id_2 = resp2.json()["id"]

        event3 = websocket.receive_json()
        assert event3["type"] == "flow"
        assert event3["data"]["id"] == flow_id_2

        # Verify no second alert event was queued/fired by broadcasting a dummy ping or checking queue state
        # In TestClient, websocket receiving when empty would block or raise error, so we test another flow and verify only flow event is received
        payload_benign = {
            "src_ip": "192.168.1.100",
            "dst_ip": "10.0.0.5",
            "dst_port": 443,
            "features": features
        }
        resp3 = client.post("/ingest/flows", json=payload_benign)
        assert resp3.status_code == 200
        flow_id_3 = resp3.json()["id"]

        event4 = websocket.receive_json()
        assert event4["type"] == "flow"
        assert event4["data"]["id"] == flow_id_3
