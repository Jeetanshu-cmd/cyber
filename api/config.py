"""
api/config.py: Configuration and artifact loading for the NIDS FastAPI service.
Loads model.pkl, features.json, and metrics.json from MODEL_DIR at startup.
"""

import os
import json
import joblib

MODEL_DIR = os.getenv("MODEL_DIR", "ml/artifacts")

FEATURES_PATH = os.path.join(MODEL_DIR, "features.json")
MODEL_PATH = os.path.join(MODEL_DIR, "model.pkl")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")

# Load features.json at import time
if not os.path.exists(FEATURES_PATH):
    raise FileNotFoundError(f"features.json not found at {FEATURES_PATH}")

with open(FEATURES_PATH, "r") as f:
    FEATURES_INFO = json.load(f)

FEATURE_LIST = FEATURES_INFO["features"]
CLASS_LIST = FEATURES_INFO["classes"]

# Load model.pkl at import time
if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(f"model.pkl not found at {MODEL_PATH}")

MODEL = joblib.load(MODEL_PATH)

# Load metrics.json at import time
METRICS_DATA = {}
if os.path.exists(METRICS_PATH):
    with open(METRICS_PATH, "r") as f:
        METRICS_DATA = json.load(f)
