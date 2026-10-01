"""
api/alerts.py: In-memory alert de-duplication tracker.
Fires alerts for non-Benign flows with confidence > ALERT_THRESHOLD, rate-limited per (src_ip, label) pair.
"""

import os
import time
from typing import Tuple, Dict

ALERT_THRESHOLD = float(os.getenv("ALERT_THRESHOLD", "0.85"))
ALERT_DEDUP_SECONDS = float(os.getenv("ALERT_DEDUP_SECONDS", "30"))

class AlertTracker:
    def __init__(self, threshold: float = ALERT_THRESHOLD, dedup_seconds: float = ALERT_DEDUP_SECONDS):
        self.threshold = threshold
        self.dedup_seconds = dedup_seconds
        # Stores (src_ip, label) -> last_alert_time (epoch seconds)
        self.last_alerts: Dict[Tuple[str, str], float] = {}

    def should_alert(self, src_ip: str, label: str, confidence: float, now: float = None) -> bool:
        if now is None:
            now = time.time()

        if label == "Benign" or confidence <= self.threshold:
            return False

        key = (src_ip, label)
        last_time = self.last_alerts.get(key)

        if last_time is not None and (now - last_time) < self.dedup_seconds:
            return False

        self.last_alerts[key] = now
        return True

    def reset(self):
        """Resets the alert de-duplication state (useful for tests)."""
        self.last_alerts.clear()

alert_tracker = AlertTracker()
