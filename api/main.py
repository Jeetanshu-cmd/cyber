"""
api/main.py: Main FastAPI application mounting routers, WebSocket endpoints, and initializing database.
"""

from contextlib import asynccontextmanager
from typing import Dict
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel

from api.config import MODEL, FEATURE_LIST, CLASS_LIST, METRICS_DATA
from api.inference import predict
from api.db import init_db
from api.ws import ws_manager

from api.routes import ingest, flows, system

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    init_db()
    yield

app = FastAPI(
    title="Network Intrusion Detection System API",
    description="Real-time network intrusion detection and classification API service.",
    version="1.0.0",
    lifespan=lifespan
)

# Mount Routers
app.include_router(ingest.router)
app.include_router(flows.router)
app.include_router(system.router)

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

@app.websocket("/ws/flows")
async def websocket_flows_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint broadcasting real-time flow classifications and security alerts.
    """
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection open for push events
            await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
