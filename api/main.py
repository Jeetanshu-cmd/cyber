"""
api/main.py: FastAPI REST API service exposing /predict, /health, and /model-info endpoints.
"""

from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from api.config import MODEL, FEATURE_LIST, CLASS_LIST, METRICS_DATA
from api.inference import predict

app = FastAPI(
    title="Network Intrusion Detection System API",
    description="Real-time network intrusion detection and classification API service.",
    version="1.0.0"
)

class PredictRequest(BaseModel):
    features: Dict[str, float]

@app.get("/health")
def health_check():
    """Health check endpoint indicating API operational status and model load state."""
    return {
        "status": "ok",
        "model_loaded": MODEL is not None
    }

@app.get("/model-info")
def model_info():
    """Returns model metadata, contract feature order, class list, and evaluation metrics."""
    return {
        "model_type": MODEL.__class__.__name__ if MODEL is not None else "Unknown",
        "features": FEATURE_LIST,
        "classes": CLASS_LIST,
        "metrics": METRICS_DATA
    }

@app.post("/predict")
def predict_endpoint(request: PredictRequest):
    """
    Stateless intrusion prediction endpoint.
    Accepts 19 flow features and returns predicted label, confidence, and top features.
    """
    try:
        result = predict(request.features)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
