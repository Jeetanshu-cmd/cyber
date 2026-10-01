# AI-Powered Network Intrusion Detection System (NIDS)

An intelligent, real-time Network Intrusion Detection System (NIDS) leveraging Machine Learning to detect, classify, and mitigate malicious network traffic patterns including DoS/DDoS attacks, Port Scans, and Brute Force intrusions.

---

## 📌 Project Overview

This project bridges offline Machine Learning training on benchmark intrusion datasets (**CICIDS2017**) with live packet capture and real-time telemetry analysis. It uses a **19-feature network flow contract** to extract key packet length, timing, and TCP flag metrics, classifying network activity into four distinct target categories:

- **`Benign`**: Normal, authorized network traffic.
- **`DoS_DDoS`**: Denial of Service & Distributed Denial of Service attacks (e.g., DoS Hulk, GoldenEye, Slowloris, Slowhttptest, DDoS).
- **`PortScan`**: Reconnaissance and vulnerability scanning activity.
- **`BruteForce`**: Automated authentication attacks (e.g., FTP-Patator, SSH-Patator).

---

## 🏗️ Project Architecture & Folder Structure

```
Cyber/
├── api/                # FastAPI backend & REST API endpoints
│   ├── routes/         # API route handlers
│   └── tests/          # API integration tests
├── capture/            # Real-time network packet capture & flow feature extraction (Scapy)
├── dashboard/          # Monitoring web interface & visualization dashboard
├── data/               # Raw and processed datasets
│   └── raw/            # CICIDS2017 benchmark CSV datasets
├── docs/               # System documentation & architectural diagrams
├── ml/                 # Machine learning pipeline & artifacts
│   ├── artifacts/      # Exported models, feature specs, metrics, & plots
│   │   ├── model.pkl               # Trained Random Forest model
│   │   ├── features.json           # 19-feature contract specification
│   │   ├── metrics.json            # Model evaluation metrics & audit trail
│   │   ├── held_out_sample.csv     # Stratified sample reserved for replay testing
│   │   ├── confusion_matrix.png    # Evaluation confusion matrix plot
│   │   └── feature_importance.png  # Feature importance visualization
│   ├── train.py        # ML training, preprocessing, & evaluation pipeline
│   └── test_model.py   # Model artifact integrity & inference test script
├── .env.example        # Environment variables configuration template
├── .gitignore          # Git exclusion rules
├── requirements.txt    # Python dependencies
└── test_setup.py       # Setup & skeleton verification test
```

---

## ⚡ 19-Feature Network Flow Contract

The machine learning pipeline operates on a standardized **19-feature contract** extracted per network flow:

| # | Feature Name | Description | Source / Unit |
|---|---|---|---|
| 1 | `dst_port` | Destination Port Number | Header / Port Number |
| 2 | `flow_duration_s` | Total duration of the flow | Calculated (Seconds) |
| 3 | `total_fwd_packets` | Total forward packets count | Packet Count |
| 4 | `total_bwd_packets` | Total backward packets count | Packet Count |
| 5 | `total_fwd_bytes` | Total volume of forward payload | Bytes |
| 6 | `total_bwd_bytes` | Total volume of backward payload | Bytes |
| 7 | `pkt_len_min` | Minimum packet length in flow | Bytes |
| 8 | `pkt_len_max` | Maximum packet length in flow | Bytes |
| 9 | `pkt_len_mean` | Average packet length | Bytes |
| 10 | `pkt_len_std` | Standard deviation of packet length | Bytes |
| 11 | `flow_bytes_s` | Flow throughput in bytes/second | Bytes / Sec |
| 12 | `flow_pkts_s` | Flow throughput in packets/second | Packets / Sec |
| 13 | `flow_iat_mean` | Mean Inter-Arrival Time between packets | Calculated (Seconds) |
| 14 | `flow_iat_max` | Maximum Inter-Arrival Time | Calculated (Seconds) |
| 15 | `syn_flag_cnt` | SYN TCP Flag count | Flag Count |
| 16 | `ack_flag_cnt` | ACK TCP Flag count | Flag Count |
| 17 | `fin_flag_cnt` | FIN TCP Flag count | Flag Count |
| 18 | `rst_flag_cnt` | RST TCP Flag count | Flag Count |
| 19 | `psh_flag_cnt` | PSH TCP Flag count | Flag Count |

---

## 📊 Model Performance

The primary classifier is a **Random Forest Classifier** (`150 estimators`, `class_weight="balanced"`).

| Metric | Score |
|---|---|
| **Macro-F1 (with `dst_port`)** | **99.87%** |
| **Macro-F1 (without `dst_port`)** | **99.03%** |
| **Benign Precision / Recall** | `99.83%` / `99.81%` |
| **DoS/DDoS Precision / Recall** | `99.86%` / `99.85%` |
| **PortScan Precision / Recall** | `99.90%` / `99.92%` |
| **BruteForce Precision / Recall** | `99.78%` / `99.89%` |

---

## 🚀 Quick Start Guide

### 1. Environment Setup
Create a Python virtual environment and install the required dependencies:
```bash
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

pip install -r requirements.txt
```

### 2. Verify System Setup
Run the setup test to check repository structure and package imports:
```bash
python test_setup.py
```

### 3. Train ML Model
Train the model on raw CICIDS2017 CSV datasets stored in `data/raw/`:
```bash
python ml/train.py
```

### 4. Test Model Artifacts
Verify the trained model and feature alignment against held-out samples:
```bash
python ml/test_model.py
```

---

## 🛡️ License & Contract
Designed and developed following modular security system specifications and feature contracts.