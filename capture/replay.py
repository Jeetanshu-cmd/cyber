"""
capture/replay.py: Network flow replay module.

Simulates live network flow ingestion by reading historical / benchmark flow datasets
(e.g., held-out CSV samples), fabricating plausible private IP addresses, formatting
payloads according to the 19-feature ingestion contract, and streaming them to the
FastAPI backend (/ingest/flows) at a configurable rate.
"""

import argparse
import logging
import random
import sys
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import httpx
import pandas as pd

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("flow_replay")


def generate_plausible_ips() -> Tuple[str, str]:
    """
    Fabricates plausible private network IP addresses for demonstration.
    """
    src_subnet = random.choice(["192.168.1", "10.0.0", "172.16.0"])
    dst_subnet = random.choice(["192.168.1", "10.0.0", "172.16.0"])
    src_ip = f"{src_subnet}.{random.randint(2, 254)}"
    dst_ip = f"{dst_subnet}.{random.randint(2, 254)}"
    return src_ip, dst_ip


def prepare_flow_payload(
    row_dict: Dict[str, Any],
    src_ip: Optional[str] = None,
    dst_ip: Optional[str] = None,
) -> Tuple[Dict[str, Any], Optional[str]]:
    """
    Prepares an ingestion payload from a CSV row dictionary.

    - Extracts and removes 'ground_truth_label' (if present) for local verification.
    - Fabricates plausible IPs if not explicitly supplied.
    - Extracts 'dst_port' as an integer for top-level payload.
    - Converts all feature values to float.

    Returns:
        tuple: (payload_dict, ground_truth_label)
    """
    row_copy = dict(row_dict)

    # Extract ground truth label locally without sending to API
    ground_truth = None
    for label_key in ["ground_truth_label", "Label", "label", "ground_truth"]:
        if label_key in row_copy:
            val = row_copy.pop(label_key)
            if pd.notna(val):
                ground_truth = str(val).strip()
            break

    # Extract destination port
    dst_port_raw = row_copy.get("dst_port", 80)
    try:
        dst_port = int(float(dst_port_raw))
    except (ValueError, TypeError):
        dst_port = 80

    # Fabricate IP addresses if not provided
    if not src_ip or not dst_ip:
        fab_src, fab_dst = generate_plausible_ips()
        src_ip = src_ip or fab_src
        dst_ip = dst_ip or fab_dst

    # Ensure all feature values are numeric floats
    features: Dict[str, float] = {}
    for k, v in row_copy.items():
        try:
            features[k] = float(v)
        except (ValueError, TypeError):
            features[k] = 0.0

    payload = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "dst_port": dst_port,
        "features": features,
    }

    return payload, ground_truth


def send_flow(
    api_url: str,
    payload: Dict[str, Any],
    client: Optional[httpx.Client] = None,
    max_retries: int = 1,
    timeout: float = 5.0,
) -> Optional[Dict[str, Any]]:
    """
    Sends a flow payload to {api_url}/ingest/flows via POST.
    Retries once on connection failure; skips and logs on repeated failure.
    """
    target_url = f"{api_url.rstrip('/')}/ingest/flows"
    attempts = 0
    should_close_client = False

    if client is None:
        client = httpx.Client(timeout=timeout)
        should_close_client = True

    try:
        while attempts <= max_retries:
            attempts += 1
            try:
                response = client.post(target_url, json=payload)
                if response.status_code == 200:
                    return response.json()
                else:
                    logger.warning(
                        "API returned status %d: %s (attempt %d/%d)",
                        response.status_code,
                        response.text,
                        attempts,
                        max_retries + 1,
                    )
            except (httpx.RequestError, httpx.HTTPError) as exc:
                logger.warning(
                    "HTTP request error: %s (attempt %d/%d)",
                    exc,
                    attempts,
                    max_retries + 1,
                )

            if attempts <= max_retries:
                time.sleep(0.5)  # brief pause before retry

        logger.error(
            "Failed to post flow to %s after %d attempt(s). Skipping row.",
            target_url,
            attempts,
        )
        return None
    finally:
        if should_close_client:
            client.close()


def replay_flows(
    csv_path: str = "ml/artifacts/held_out_sample.csv",
    rate: float = 5.0,
    api_url: str = "http://localhost:8000",
    client: Optional[httpx.Client] = None,
) -> Dict[str, Any]:
    """
    Replays flows from CSV at the specified rate to the API endpoint.
    Tracks running prediction accuracy against local ground truth labels.
    """
    csv_file = Path(csv_path)
    if not csv_file.exists():
        raise FileNotFoundError(f"CSV dataset not found at {csv_path}")

    df = pd.read_csv(csv_file)
    total_rows = len(df)
    logger.info("Loaded %d rows from %s", total_rows, csv_path)
    logger.info("Target API: %s/ingest/flows | Rate: %.2f rows/sec", api_url.rstrip('/'), rate)

    delay = 1.0 / rate if rate > 0 else 0.0

    total_evaluated = 0
    total_correct = 0
    total_sent = 0
    total_failed = 0

    should_close_client = False
    if client is None:
        client = httpx.Client(timeout=5.0)
        should_close_client = True

    start_time = time.time()

    try:
        for idx, row in df.iterrows():
            row_idx = idx + 1
            payload, ground_truth = prepare_flow_payload(row.to_dict())

            result = send_flow(api_url=api_url, payload=payload, client=client)

            if result is None:
                total_failed += 1
                print(f"[Row {row_idx}/{total_rows}] FAILED to send payload. Skipped.")
            else:
                total_sent += 1
                predicted_label = result.get("label", "Unknown")
                confidence = result.get("confidence", 0.0)

                if ground_truth is not None:
                    total_evaluated += 1
                    is_match = predicted_label == ground_truth
                    if is_match:
                        total_correct += 1

                    running_acc = (total_correct / total_evaluated) * 100.0
                    match_str = "MATCH" if is_match else "MISMATCH"
                    print(
                        f"[Row {row_idx}/{total_rows}] Pred: {predicted_label:<10} ({confidence:.1%}) | "
                        f"Truth: {ground_truth:<10} | [{match_str}] | "
                        f"Running Accuracy: {running_acc:6.2f}% ({total_correct}/{total_evaluated})"
                    )
                else:
                    print(
                        f"[Row {row_idx}/{total_rows}] Pred: {predicted_label:<10} ({confidence:.1%}) | "
                        f"Truth: N/A"
                    )

            if delay > 0 and row_idx < total_rows:
                time.sleep(delay)

    finally:
        if should_close_client:
            client.close()

    elapsed = time.time() - start_time
    final_accuracy = (total_correct / total_evaluated * 100.0) if total_evaluated > 0 else 0.0

    print("\n" + "=" * 60)
    print("REPLAY COMPLETE SUMMARY")
    print("=" * 60)
    print(f"Total Rows in Dataset : {total_rows}")
    print(f"Successfully Sent     : {total_sent}")
    print(f"Failed / Skipped      : {total_failed}")
    print(f"Ground Truth Evaluated: {total_evaluated}")
    print(f"Correct Predictions   : {total_correct}")
    print(f"Final Running Accuracy: {final_accuracy:.2f}%")
    print(f"Total Time Elapsed    : {elapsed:.2f}s")
    print("=" * 60 + "\n")

    return {
        "total_rows": total_rows,
        "sent": total_sent,
        "failed": total_failed,
        "evaluated": total_evaluated,
        "correct": total_correct,
        "accuracy": final_accuracy,
        "elapsed_seconds": elapsed,
    }


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Replay network flow CSV data to the NIDS ingestion API."
    )
    parser.add_argument(
        "--csv",
        type=str,
        default="ml/artifacts/held_out_sample.csv",
        help="Path to CSV dataset (default: ml/artifacts/held_out_sample.csv)",
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=5.0,
        help="Replay rate in rows per second (default: 5.0)",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default="http://localhost:8000",
        help="Base URL of the NIDS API (default: http://localhost:8000)",
    )
    return parser.parse_args(argv)


def main():
    args = parse_args()
    try:
        replay_flows(
            csv_path=args.csv,
            rate=args.rate,
            api_url=args.api_url,
        )
    except KeyboardInterrupt:
        print("\nReplay interrupted by user. Exiting.")
        sys.exit(0)
    except Exception as e:
        logger.error("Replay encountered an error: %s", e)
        sys.exit(1)


if __name__ == "__main__":
    main()
