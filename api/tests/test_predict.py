"""
api/tests/test_predict.py: Unit and integration tests for FastAPI endpoints (/predict, /health, /model-info).
"""

import json
import pandas as pd
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert data["model_loaded"] is True

def test_model_info_endpoint():
    response = client.get("/model-info")
    assert response.status_code == 200
    data = response.json()
    assert "model_type" in data
    assert "features" in data
    assert "classes" in data
    assert "metrics" in data
    assert isinstance(data["features"], list)
    assert len(data["features"]) == 19

def test_valid_predict_request():
    held_out_df = pd.read_csv("ml/artifacts/held_out_sample.csv")
    sample_row = held_out_df.iloc[0].to_dict()
    ground_truth = sample_row.pop("ground_truth_label")

    response = client.post("/predict", json={"features": sample_row})
    assert response.status_code == 200
    data = response.json()

    assert "label" in data
    assert "confidence" in data
    assert "top_features" in data
    assert isinstance(data["label"], str)
    assert 0.0 <= data["confidence"] <= 1.0
    assert len(data["top_features"]) == 5

    for item in data["top_features"]:
        assert "feature" in item
        assert "importance" in item
        assert "value" in item

def test_predict_missing_feature_rejected():
    held_out_df = pd.read_csv("ml/artifacts/held_out_sample.csv")
    sample_row = held_out_df.iloc[0].to_dict()
    sample_row.pop("ground_truth_label")
    
    # Remove one required feature
    sample_row.pop("dst_port")

    response = client.post("/predict", json={"features": sample_row})
    assert response.status_code == 400
    data = response.json()
    assert "Missing required feature(s)" in data["detail"]
    assert "dst_port" in data["detail"]

def test_predict_extra_feature_rejected():
    held_out_df = pd.read_csv("ml/artifacts/held_out_sample.csv")
    sample_row = held_out_df.iloc[0].to_dict()
    sample_row.pop("ground_truth_label")

    # Add an unexpected feature
    sample_row["unexpected_extra_feature"] = 999.0

    response = client.post("/predict", json={"features": sample_row})
    assert response.status_code == 400
    data = response.json()
    assert "Unexpected extra feature(s)" in data["detail"]
    assert "unexpected_extra_feature" in data["detail"]
