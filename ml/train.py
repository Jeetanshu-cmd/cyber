"""
ml/train.py: Pipeline to load CICIDS2017 raw dataset, preprocess, clean, split, train Random Forest classifier models, evaluate variants (with/without dst_port), and export artifacts.

19 Feature Contract (AGENTS.md §3):
1. dst_port
2. flow_duration_s (Flow Duration in seconds)
3. total_fwd_packets
4. total_bwd_packets
5. total_fwd_bytes
6. total_bwd_bytes
7. pkt_len_min
8. pkt_len_max
9. pkt_len_mean
10. pkt_len_std
11. flow_bytes_s
12. flow_pkts_s
13. flow_iat_mean (Flow IAT Mean in seconds)
14. flow_iat_max (Flow IAT Max in seconds)
15. syn_flag_cnt
16. ack_flag_cnt
17. fin_flag_cnt
18. rst_flag_cnt
19. psh_flag_cnt

Traced Example (3 raw CICIDS rows -> renamed/converted -> cleaned -> encoded):
Raw Row 1:
  Destination Port: 54865, Flow Duration: 3 (us), Total Fwd Packets: 2, Total Backward Packets: 0,
  Total Length of Fwd Packets: 12, Total Length of Bwd Packets: 0, Min Packet Length: 6, Max Packet Length: 6,
  Packet Length Mean: 6, Packet Length Std: 0, SYN Flag Count: 0, ACK Flag Count: 0, ...
  Label: BENIGN
Renamed & Converted Row 1:
  dst_port: 54865.0, flow_duration_s: 0.000003, total_fwd_packets: 2.0, total_bwd_packets: 0.0,
  total_fwd_bytes: 12.0, total_bwd_bytes: 0.0, pkt_len_min: 6.0, pkt_len_max: 6.0, pkt_len_mean: 6.0, ...
  Label: Benign
Cleaned Row 1:
  Passed (no inf/NaN, not a duplicate).
Encoded Label Row 1:
  ground_truth_label: "Benign"

Raw Row 2:
  Destination Port: 80, Flow Duration: 1500000 (us), Total Fwd Packets: 10, ...
  Label: DoS Hulk
Renamed & Converted Row 2:
  dst_port: 80.0, flow_duration_s: 1.5, ...
  Label: DoS_DDoS
Cleaned Row 2:
  Passed.

Raw Row 3:
  Destination Port: 21, Flow Duration: inf, Total Fwd Packets: 1, ...
  Label: FTP-Patator
Renamed & Converted Row 3:
  dst_port: 21.0, flow_duration_s: inf, ...
  Label: BruteForce
Cleaned Row 3:
  Dropped (contains inf -> NaN).

Time Complexity:
- Training: O(N_samples * N_trees * N_features * log(N_samples))
  For N_samples <= 600,000, N_trees = 150, N_features = 19.
- Single Prediction: O(N_trees * max_depth)
  For N_trees = 150, typical depth ~ 20-30 operations per prediction (sub-millisecond latency).
"""

import os
import glob
import json
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, ConfusionMatrixDisplay

# Define updated 19 features contract mapping (Raw CICIDS Column Name -> Contract Feature Name)
RAW_TO_CONTRACT = {
    'Destination Port': 'dst_port',
    'Flow Duration': 'flow_duration_s',
    'Total Fwd Packets': 'total_fwd_packets',
    'Total Backward Packets': 'total_bwd_packets',
    'Total Length of Fwd Packets': 'total_fwd_bytes',
    'Total Length of Bwd Packets': 'total_bwd_bytes',
    'Min Packet Length': 'pkt_len_min',
    'Max Packet Length': 'pkt_len_max',
    'Packet Length Mean': 'pkt_len_mean',
    'Packet Length Std': 'pkt_len_std',
    'Flow Bytes/s': 'flow_bytes_s',
    'Flow Packets/s': 'flow_pkts_s',
    'Flow IAT Mean': 'flow_iat_mean',
    'Flow IAT Max': 'flow_iat_max',
    'SYN Flag Count': 'syn_flag_cnt',
    'ACK Flag Count': 'ack_flag_cnt',
    'FIN Flag Count': 'fin_flag_cnt',
    'RST Flag Count': 'rst_flag_cnt',
    'PSH Flag Count': 'psh_flag_cnt',
}

FEATURE_ORDER = list(RAW_TO_CONTRACT.values())
MICROSECOND_COLUMNS = ['flow_duration_s', 'flow_iat_mean', 'flow_iat_max']

LABEL_MAP = {
    'BENIGN': 'Benign',
    'DDoS': 'DoS_DDoS',
    'DoS GoldenEye': 'DoS_DDoS',
    'DoS Hulk': 'DoS_DDoS',
    'DoS Slowhttptest': 'DoS_DDoS',
    'DoS slowloris': 'DoS_DDoS',
    'PortScan': 'PortScan',
    'FTP-Patator': 'BruteForce',
    'SSH-Patator': 'BruteForce',
}

TARGET_CLASSES = sorted(list(set(LABEL_MAP.values())))

def main():
    os.makedirs('ml/artifacts', exist_ok=True)
    raw_files = glob.glob('data/raw/*.csv')
    if not raw_files:
        raise FileNotFoundError("No raw CSV files found in data/raw/")

    print(f"Loading {len(raw_files)} CSV files...")
    df_list = []

    for f in raw_files:
        header_df = pd.read_csv(f, nrows=1, encoding='latin-1')
        stripped_cols = {col: col.strip() for col in header_df.columns}
        
        usecols_map = {}
        for raw_col, contract_name in RAW_TO_CONTRACT.items():
            found = False
            for orig_col, stripped in stripped_cols.items():
                if stripped == raw_col:
                    usecols_map[orig_col] = contract_name
                    found = True
                    break
            if not found:
                raise ValueError(f"Missing required raw column '{raw_col}' in file {f}")
        
        label_orig_col = None
        for orig_col, stripped in stripped_cols.items():
            if stripped == 'Label':
                label_orig_col = orig_col
                break
        if not label_orig_col:
            raise ValueError(f"Missing 'Label' column in file {f}")
        
        load_cols = list(usecols_map.keys()) + [label_orig_col]
        
        df_chunk = pd.read_csv(f, usecols=load_cols, encoding='latin-1')
        df_chunk = df_chunk.rename(columns=usecols_map)
        df_chunk = df_chunk.rename(columns={label_orig_col: 'raw_label'})
        df_list.append(df_chunk)

    df_full = pd.concat(df_list, ignore_index=True)
    print(f"Initial total rows loaded: {len(df_full)}")

    # 1. Feature casting & duration conversions
    for col in FEATURE_ORDER:
        df_full[col] = df_full[col].astype('float32')
    
    for col in MICROSECOND_COLUMNS:
        df_full[col] = df_full[col] / 1000000.0

    # 2. Clean: replace inf with NaN, drop NaN rows, drop duplicates BEFORE splitting
    df_full.replace([np.inf, -np.inf], np.nan, inplace=True)
    rows_before_nan = len(df_full)
    df_full.dropna(subset=FEATURE_ORDER + ['raw_label'], inplace=True)
    print(f"Rows after dropping NaN/inf: {len(df_full)} (dropped {rows_before_nan - len(df_full)})")

    rows_before_dup = len(df_full)
    df_full.drop_duplicates(inplace=True)
    print(f"Rows after dropping exact duplicates: {len(df_full)} (dropped {rows_before_dup - len(df_full)})")

    # 3. Map labels to target 4 classes, drop others
    df_full['raw_label'] = df_full['raw_label'].astype(str).str.strip()
    df_full['label'] = df_full['raw_label'].map(LABEL_MAP)
    rows_before_label_drop = len(df_full)
    df_full.dropna(subset=['label'], inplace=True)
    print(f"Rows after dropping unmapped classes: {len(df_full)} (dropped {rows_before_label_drop - len(df_full)})")

    print("\nClass distribution after cleaning:")
    print(df_full['label'].value_counts())

    # 4. Cap each class at 150,000 rows (random seed 42)
    capped_chunks = []
    for cls, group in df_full.groupby('label'):
        if len(group) > 150000:
            sampled = group.sample(n=150000, random_state=42)
            capped_chunks.append(sampled)
        else:
            capped_chunks.append(group)
    df_capped = pd.concat(capped_chunks, ignore_index=True)
    print("\nClass distribution after capping (max 150,000 per class):")
    cicids_counts = df_capped['label'].value_counts().to_dict()
    print(cicids_counts)

    # 5. Carve out ml/artifacts/held_out_sample.csv: 200 rows per class (stratified)
    held_out_chunks = []
    train_pool_chunks = []
    for cls, group in df_capped.groupby('label'):
        n_held_out = min(200, len(group))
        held_out = group.sample(n=n_held_out, random_state=42)
        train_pool = group.drop(held_out.index)
        held_out_chunks.append(held_out)
        train_pool_chunks.append(train_pool)
    
    held_out_df = pd.concat(held_out_chunks, ignore_index=True)
    train_pool_df = pd.concat(train_pool_chunks, ignore_index=True)

    # Save held_out_sample.csv with plain header (19 features + ground_truth_label)
    held_out_export = held_out_df[FEATURE_ORDER + ['label']].rename(columns={'label': 'ground_truth_label'})
    held_out_path = 'ml/artifacts/held_out_sample.csv'
    held_out_export.to_csv(held_out_path, index=False)
    print(f"\nSaved held-out sample ({len(held_out_export)} rows) to {held_out_path}")

    # 6. Stratified 80/20 train/test split on train pool
    X = train_pool_df[FEATURE_ORDER]
    y = train_pool_df['label']

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    print(f"\nTraining set size: {len(X_train)}, Test set size: {len(X_test)}")

    # 7. Train two variants: Variant A (with dst_port) and Variant B (without dst_port)
    features_variant_a = FEATURE_ORDER
    features_variant_b = [f for f in FEATURE_ORDER if f != 'dst_port']

    print("\nTraining Variant A (with dst_port)...")
    clf_a = RandomForestClassifier(n_estimators=150, n_jobs=-1, class_weight="balanced", random_state=42)
    clf_a.fit(X_train[features_variant_a], y_train)
    y_pred_a = clf_a.predict(X_test[features_variant_a])
    report_a = classification_report(y_test, y_pred_a, output_dict=True)

    print("\nTraining Variant B (without dst_port)...")
    clf_b = RandomForestClassifier(n_estimators=150, n_jobs=-1, class_weight="balanced", random_state=42)
    clf_b.fit(X_train[features_variant_b], y_train)
    y_pred_b = clf_b.predict(X_test[features_variant_b])
    report_b = classification_report(y_test, y_pred_b, output_dict=True)

    macro_f1_a = report_a['macro avg']['f1-score']
    macro_f1_b = report_b['macro avg']['f1-score']

    print(f"\nVariant A (with dst_port) Macro-F1: {macro_f1_a:.4f}")
    print(f"Variant B (without dst_port) Macro-F1: {macro_f1_b:.4f}")

    if macro_f1_a >= macro_f1_b:
        best_model = clf_a
        best_features = features_variant_a
        best_variant = "with_dst_port"
        best_pred = y_pred_a
        print("Selected Variant A (with dst_port) as the primary model.")
    else:
        best_model = clf_b
        best_features = features_variant_b
        best_variant = "without_dst_port"
        best_pred = y_pred_b
        print("Selected Variant B (without dst_port) as the primary model.")

    # 8. Export Artifacts
    joblib.dump(best_model, 'ml/artifacts/model.pkl')
    print("Saved model to ml/artifacts/model.pkl")

    features_json_data = {
        "features": best_features,
        "classes": TARGET_CLASSES,
        "has_dst_port": 'dst_port' in best_features,
        "selected_variant": best_variant
    }
    with open('ml/artifacts/features.json', 'w') as f:
        json.dump(features_json_data, f, indent=2)
    print("Saved features.json to ml/artifacts/features.json")

    metrics_data = {
        "selected_variant": best_variant,
        "variant_a_with_dst_port": {
            "macro_f1": macro_f1_a,
            "report": report_a
        },
        "variant_b_without_dst_port": {
            "macro_f1": macro_f1_b,
            "report": report_b
        },
        "data_sources": {
            "cicids2017": cicids_counts,
            "local_capture": 0
        }
    }
    with open('ml/artifacts/metrics.json', 'w') as f:
        json.dump(metrics_data, f, indent=2)
    print("Saved metrics.json to ml/artifacts/metrics.json")

    # Save confusion_matrix.png
    cm = confusion_matrix(y_test, best_pred, labels=TARGET_CLASSES)
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=TARGET_CLASSES)
    fig, ax = plt.subplots(figsize=(8, 6))
    disp.plot(ax=ax, cmap='Blues', values_format='d')
    plt.title(f"Confusion Matrix ({best_variant})")
    plt.tight_layout()
    plt.savefig('ml/artifacts/confusion_matrix.png')
    plt.close()
    print("Saved confusion_matrix.png to ml/artifacts/confusion_matrix.png")

    # Save feature_importance.png
    importances = best_model.feature_importances_
    indices = np.argsort(importances)[::-1]
    sorted_features = [best_features[i] for i in indices]
    sorted_importances = importances[indices]

    plt.figure(figsize=(10, 6))
    plt.barh(range(len(sorted_features)), sorted_importances[::-1], align='center')
    plt.yticks(range(len(sorted_features)), sorted_features[::-1])
    plt.xlabel("Feature Importance")
    plt.title(f"Random Forest Feature Importances ({best_variant})")
    plt.tight_layout()
    plt.savefig('ml/artifacts/feature_importance.png')
    plt.close()
    print("Saved feature_importance.png to ml/artifacts/feature_importance.png")

    print("\nML Training pipeline executed successfully.")

if __name__ == '__main__':
    main()
