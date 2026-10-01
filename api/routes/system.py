"""
api/routes/system.py: System analytics and statistics endpoints (GET /stats).
"""

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func

from api.db import get_db, FlowModel

router = APIRouter()

@router.get("/stats")
def get_system_stats(
    minutes: int = Query(60, ge=1, description="Time window in minutes for flow label aggregation"),
    db: Session = Depends(get_db)
):
    """
    Returns flow counts grouped by label for all flows recorded in the last N minutes.
    """
    cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    results = (
        db.query(FlowModel.label, func.count(FlowModel.id))
        .filter(FlowModel.timestamp >= cutoff_time)
        .group_by(FlowModel.label)
        .all()
    )

    stats_dict = {label: count for label, count in results}

    return {
        "time_window_minutes": minutes,
        "counts_by_label": stats_dict
    }
