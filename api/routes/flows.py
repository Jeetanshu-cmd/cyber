"""
api/routes/flows.py: Query endpoints for retrieving persisted network flows (GET /flows, GET /flows/{id}).
"""

from typing import Optional, List
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.db import get_db, FlowModel

router = APIRouter()

def format_flow_dict(flow: FlowModel) -> dict:
    return {
        "id": flow.id,
        "timestamp": flow.timestamp.isoformat() if flow.timestamp else None,
        "src_ip": flow.src_ip,
        "dst_ip": flow.dst_ip,
        "dst_port": flow.dst_port,
        "label": flow.label,
        "confidence": flow.confidence,
        "features": flow.features,
        "top_features": flow.top_features
    }

@router.get("/flows")
def list_flows(
    label: Optional[str] = Query(None, description="Filter by attack label"),
    src_ip: Optional[str] = Query(None, description="Filter by source IP address"),
    start_time: Optional[datetime] = Query(None, description="Filter flows on or after start time"),
    end_time: Optional[datetime] = Query(None, description="Filter flows on or before end time"),
    limit: int = Query(50, ge=1, le=1000, description="Page size limit"),
    offset: int = Query(0, ge=0, description="Offset position"),
    db: Session = Depends(get_db)
):
    """
    Returns a paginated list of persisted network flows, with optional filtering.
    """
    query = db.query(FlowModel)

    if label:
        query = query.filter(FlowModel.label == label)
    if src_ip:
        query = query.filter(FlowModel.src_ip == src_ip)
    if start_time:
        query = query.filter(FlowModel.timestamp >= start_time)
    if end_time:
        query = query.filter(FlowModel.timestamp <= end_time)

    total_count = query.count()
    flows = query.order_by(FlowModel.id.desc()).offset(offset).limit(limit).all()

    return {
        "total": total_count,
        "limit": limit,
        "offset": offset,
        "flows": [format_flow_dict(f) for f in flows]
    }

@router.get("/flows/{flow_id}")
def get_flow_by_id(flow_id: int, db: Session = Depends(get_db)):
    """
    Retrieves a single network flow record by its unique database ID.
    """
    flow = db.query(FlowModel).filter(FlowModel.id == flow_id).first()
    if not flow:
        raise HTTPException(status_code=404, detail=f"Flow with ID {flow_id} not found")
    return format_flow_dict(flow)
