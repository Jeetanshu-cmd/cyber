"""
api/inference.py: Inference engine for Network Intrusion Detection System.

Traced Execution Example for POST /predict:
1. Input dict received:
   {"features": {"dst_port": 80.0, "flow_duration_s": 0.05, "fwd_packets": 2.0, ...}}
2. Validation:
   Checks input keys against FEATURE_LIST loaded from features.json.
   - If key count != 19 or missing/extra keys exist -> raises ValueError with explicit key list.
3. Feature Ordering:
   Extracts values in exact order of FEATURE_LIST into pandas DataFrame with feature columns:
   pd.DataFrame([[80.0, 0.05, 2.0, ...]], columns=FEATURE_LIST)
4. Prediction:
   - Call MODEL.predict(df_vector) -> ["Benign"]
   - Call MODEL.predict_proba(df_vector) -> [[0.98, 0.01, 0.005, 0.005]] -> confidence = 0.98
5. Top Features Calculation:
   Identifies top 5 most important features from MODEL.feature_importances_ paired with
   the input flow's values.
6. Response returned:
   {
     "label": "Benign",
     "confidence": 0.98,
     "top_features": [
       {"feature": "dst_port", "importance": 0.1845, "value": 80.0},
       ...
     ]
   }

Time Complexity:
- Validation & Ordering: O(K) where K = 19 features -> ~O(1)
- Inference (150 decision trees of depth ~25): O(N_trees * depth) -> ~150 * 25 = 3,750 operations (~0.2 ms)
- Top 5 Feature Ranking: O(K log K) -> ~O(1)
Total latency per request: Sub-millisecond execution time (~0.5ms).
"""

import numpy as np
import pandas as pd
from api.config import MODEL, FEATURE_LIST, CLASS_LIST

def predict(features: dict) -> dict:
    """
    Predict intrusion label and confidence for a single network flow feature dictionary.

    Args:
        features: Dictionary containing exactly the 19 feature names from features.json.

    Returns:
        Dict with keys:
            - label: Predicted class name (str)
            - confidence: Confidence probability in [0, 1] (float)
            - top_features: List of top 5 features sorted by global importance with flow values
    """
    if not isinstance(features, dict):
        raise ValueError("Features input must be a dictionary.")

    input_keys = set(features.keys())
    expected_keys = set(FEATURE_LIST)

    missing_keys = sorted(list(expected_keys - input_keys))
    extra_keys = sorted(list(input_keys - expected_keys))

    if missing_keys and extra_keys:
        raise ValueError(f"Missing feature(s): {missing_keys}, Unexpected extra feature(s): {extra_keys}")
    elif missing_keys:
        raise ValueError(f"Missing required feature(s): {missing_keys}")
    elif extra_keys:
        raise ValueError(f"Unexpected extra feature(s): {extra_keys}")

    # Order feature values per FEATURE_LIST as a DataFrame to retain feature names
    ordered_values = [float(features[feat]) for feat in FEATURE_LIST]
    df_vector = pd.DataFrame([ordered_values], columns=FEATURE_LIST, dtype=np.float32)

    # Predict class & confidence
    pred_label = str(MODEL.predict(df_vector)[0])
    proba_vector = MODEL.predict_proba(df_vector)[0]
    confidence = float(np.max(proba_vector))

    # Top 5 global feature importances paired with this flow's values
    importances = MODEL.feature_importances_
    top_indices = np.argsort(importances)[::-1][:5]

    top_features = [
        {
            "feature": FEATURE_LIST[i],
            "importance": round(float(importances[i]), 4),
            "value": float(features[FEATURE_LIST[i]])
        }
        for i in top_indices
    ]

    return {
        "label": pred_label,
        "confidence": round(confidence, 4),
        "top_features": top_features
    }
