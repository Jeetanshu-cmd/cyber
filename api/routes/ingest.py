"""
api/routes/ingest.py: Flow ingestion endpoint (POST /ingest/flows).

Traced Execution Flow for POST /ingest/flows:
1. Client sends JSON payload:
   {
     "src_ip": "192.168.1.100",
     "dst_ip": "10.0.0.1",
     "dst_port": 80,
     "features": {"dst_port": 80.0, "flow_duration_s": 0.05, ...}
   }
2. Inference:
   Calls `api.inference.predict(request.features)` -> computes predicted label, confidence score,
   and top 5 feature importances.
3. Database Persistence:
   Persists flow record to SQLite database (`flows` table) via SQLAlchemy session.
4. WebSocket Broadcast (Flow Event):
   Constructs `{"type": "flow", "data": {...}}` and broadcasts to all connected clients via `ws_manager`.
   Note: If zero WebSocket clients are connected, `ws_manager.broadcast()` executes silently without error.
5. Alert Check & Broadcast (Alert Event):
   Checks `alert_tracker.should_alert(src_ip, label, confidence)`.
   - If confidence > ALERT_THRESHOLD (0.85), label != "Benign", and no alert occurred for (src_ip, label)
     in the last ALERT_DEDUP_SECONDS (30s):
     Fires and broadcasts `{"type": "alert", "data": {...}}` event over WebSocket.
6. Response:
   Returns prediction result payload containing label, confidence, top_features, and persisted flow id.
"""

from typing import Dict
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from api.db import get_db, FlowModel
from api.inference import predict
from api.alerts import alert_tracker
from api.ws import ws_manager

router = APIRouter()

class IngestFlowRequest(BaseModel):
    src_ip: str
    dst_ip: str
    dst_port: int
    features: Dict[str, float]

@router.post("/ingest/flows")
async def ingest_flow(request: IngestFlowRequest, db: Session = Depends(get_db)):
    """
    Ingests a network flow, runs inference, persists record to DB, checks alert thresholds,
    and broadcasts real-time events over WebSocket.
    """
    try:
        inference_result = predict(request.features)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    now_utc = datetime.now(timezone.utc)

    # 1. Create DB record
    db_flow = FlowModel(
        timestamp=now_utc,
        src_ip=request.src_ip,
        dst_ip=request.dst_ip,
        dst_port=request.dst_port,
        label=inference_result["label"],
        confidence=inference_result["confidence"],
        features=request.features,
        top_features=inference_result["top_features"]
    )
    db.add(db_flow)
    db.commit()
    db.refresh(db_flow)

    # 2. Construct flow event and broadcast over WebSocket
    flow_event = {
        "type": "flow",
        "data": {
            "id": db_flow.id,
            "timestamp": db_flow.timestamp.isoformat(),
            "src_ip": db_flow.src_ip,
            "dst_ip": db_flow.dst_ip,
            "dst_port": db_flow.dst_port,
            "label": db_flow.label,
            "confidence": db_flow.confidence,
            "features": db_flow.features,
            "top_features": db_flow.top_features
        }
    }
    await ws_manager.broadcast(flow_event)

    # 3. Check alert criteria and broadcast alert event if fired
    if alert_tracker.should_alert(db_flow.src_ip, db_flow.label, db_flow.confidence):
        alert_event = {
            "type": "alert",
            "data": {
                "flow_id": db_flow.id,
                "timestamp": db_flow.timestamp.isoformat(),
                "src_ip": db_flow.src_ip,
                "dst_ip": db_flow.dst_ip,
                "dst_port": db_flow.dst_port,
                "label": db_flow.label,
                "confidence": db_flow.confidence
            }
        }
        await ws_manager.broadcast(alert_event)

    return {
        "id": db_flow.id,
        "label": db_flow.label,
        "confidence": db_flow.confidence,
        "top_features": db_flow.top_features
    }
