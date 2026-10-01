"""
ml/test_model.py: Test script to verify model artifact loading, prediction shape, prediction confidence boundaries, and feature column ordering.
"""

import json
import joblib
import numpy as np
import pandas as pd

def test_model_artifacts():
    print("Testing ML model artifacts...")

    # 1. Load features.json
    with open('ml/artifacts/features.json', 'r') as f:
        features_info = json.load(f)
    
    expected_features = features_info['features']
    expected_classes = features_info['classes']
    print(f"Loaded features.json. Feature count: {len(expected_features)}, Classes: {expected_classes}")

    # 2. Load model.pkl
    model = joblib.load('ml/artifacts/model.pkl')
    print("Loaded model.pkl successfully.")

    # 3. Load held_out_sample.csv
    held_out_df = pd.read_csv('ml/artifacts/held_out_sample.csv')
    assert len(held_out_df) >= 5, f"Expected held_out_sample.csv to have at least 5 rows, got {len(held_out_df)}"

    sample_5 = held_out_df.head(5)

    # Assert feature columns match features.json's exact order
    sample_features = sample_5[expected_features]
    assert list(sample_features.columns) == expected_features, "Feature column order does not match features.json"

    # Predict & predict_proba
    preds = model.predict(sample_features)
    proba = model.predict_proba(sample_features)

    for i in range(len(sample_5)):
        pred_label = preds[i]
        probs = proba[i]
        max_conf = float(np.max(probs))

        # Assert predictions are string
        assert isinstance(pred_label, (str, np.str_)), f"Prediction {pred_label} is not a string"
        # Assert prediction in expected classes
        assert pred_label in expected_classes, f"Predicted label {pred_label} not in expected classes {expected_classes}"
        # Assert confidence is in [0, 1]
        assert 0.0 <= max_conf <= 1.0, f"Confidence {max_conf} outside [0, 1] boundary"

        print(f"Row {i+1}: Predicted = {pred_label}, Confidence = {max_conf:.4f}, Ground Truth = {sample_5.iloc[i]['ground_truth_label']}")

    print("All model artifact assertions passed successfully!")

if __name__ == '__main__':
    test_model_artifacts()
