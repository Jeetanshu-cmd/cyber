"""
docs/score_live_eval.py: Scorer for live intrusion evaluation windows.

Queries flows recorded by the NIDS API within a given timestamp range (GET /flows),
compares predicted classifications against the expected attack scenario, prints an
accuracy report, and appends the result to docs/live_eval_results.json.
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("score_live_eval")

SCENARIO_MAP = {
    "benign": "Benign",
    "portscan": "PortScan",
    "port_scan": "PortScan",
    "dos": "DoS_DDoS",
    "ddos": "DoS_DDoS",
    "dos_ddos": "DoS_DDoS",
    "bruteforce": "BruteForce",
    "brute_force": "BruteForce",
}


def normalize_scenario_label(scenario: str) -> str:
    """Maps user-friendly CLI scenario names to model class names."""
    normalized = scenario.strip().lower()
    if normalized in SCENARIO_MAP:
        return SCENARIO_MAP[normalized]
    # Fallback to Title case if not in map
    return scenario.strip()


def fetch_flows_for_window(
    start_time: str,
    end_time: str,
    api_url: str = "http://localhost:8000",
    client: Optional[httpx.Client] = None,
) -> List[Dict[str, Any]]:
    """
    Queries GET /flows from the API with start_time and end_time filters,
    paginating until all flows in the window are retrieved.
    """
    target_url = f"{api_url.rstrip('/')}/flows"
    all_flows: List[Dict[str, Any]] = []
    offset = 0
    limit = 500
    should_close = False

    if client is None:
        client = httpx.Client(timeout=10.0)
        should_close = True

    try:
        while True:
            params = {
                "start_time": start_time,
                "end_time": end_time,
                "limit": limit,
                "offset": offset,
            }
            resp = client.get(target_url, params=params)
            if resp.status_code != 200:
                logger.error(
                    "Failed to query /flows (HTTP %d): %s",
                    resp.status_code,
                    resp.text,
                )
                break

            data = resp.json()
            flows = data.get("flows", [])
            all_flows.extend(flows)

            total = data.get("total", len(all_flows))
            offset += len(flows)

            if offset >= total or len(flows) == 0:
                break

        return all_flows
    finally:
        if should_close:
            client.close()


def score_scenario(
    flows: List[Dict[str, Any]],
    expected_scenario: str,
    start_time: str,
    end_time: str,
) -> Dict[str, Any]:
    """
    Evaluates a list of flow records against an expected scenario label.
    """
    expected_label = normalize_scenario_label(expected_scenario)
    total_flows = len(flows)
    correct_count = 0
    incorrect_count = 0
    label_distribution: Dict[str, int] = {}

    for flow in flows:
        pred_label = flow.get("label", "Unknown")
        label_distribution[pred_label] = label_distribution.get(pred_label, 0) + 1

        if pred_label == expected_label:
            correct_count += 1
        else:
            incorrect_count += 1

    accuracy = (correct_count / total_flows * 100.0) if total_flows > 0 else 0.0

    result = {
        "timestamp_evaluated": datetime.now(timezone.utc).isoformat(),
        "start_time": start_time,
        "end_time": end_time,
        "expected_scenario": expected_scenario,
        "expected_label": expected_label,
        "total_flows": total_flows,
        "correct_predictions": correct_count,
        "incorrect_predictions": incorrect_count,
        "accuracy_pct": round(accuracy, 2),
        "label_distribution": label_distribution,
    }
    return result


def append_result_to_json(result: Dict[str, Any], output_path: str = "docs/live_eval_results.json") -> None:
    """
    Appends the evaluation result record to the JSON file, accumulating test runs.
    """
    file_path = Path(output_path)
    records = []

    if file_path.exists():
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if content:
                    records = json.loads(content)
                    if not isinstance(records, list):
                        records = [records]
        except Exception as e:
            logger.warning("Could not parse existing results file (%s). Overwriting with new list.", e)
            records = []

    records.append(result)

    file_path.parent.mkdir(parents=True, exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(records, f, indent=2)

    logger.info("Evaluation results saved to %s", output_path)


def print_evaluation_summary(result: Dict[str, Any]) -> None:
    """Prints a clean CLI summary table."""
    print("\n" + "=" * 60)
    print("LIVE EVALUATION WINDOW SUMMARY")
    print("=" * 60)
    print(f"Time Window        : {result['start_time']} -> {result['end_time']}")
    print(f"Expected Scenario  : {result['expected_scenario']} ({result['expected_label']})")
    print(f"Total Flows Scored : {result['total_flows']}")
    print(f"Correct Matches    : {result['correct_predictions']}")
    print(f"Incorrect / Other  : {result['incorrect_predictions']}")
    print(f"Scenario Accuracy  : {result['accuracy_pct']:.2f}%")
    print("Prediction Breakdown:")
    for lbl, count in result["label_distribution"].items():
        pct = (count / result["total_flows"] * 100.0) if result["total_flows"] > 0 else 0.0
        print(f"  - {lbl:<12} : {count:4d} ({pct:5.1f}%)")
    print("=" * 60 + "\n")


def parse_args(argv: Optional[list] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Score live evaluation flows against expected ground truth scenario."
    )
    parser.add_argument(
        "--start",
        type=str,
        required=True,
        help="Start timestamp of evaluation window (ISO format, e.g. '2026-10-02T17:00:00')",
    )
    parser.add_argument(
        "--end",
        type=str,
        required=True,
        help="End timestamp of evaluation window (ISO format, e.g. '2026-10-02T17:05:00')",
    )
    parser.add_argument(
        "--expected",
        type=str,
        required=True,
        choices=["benign", "portscan", "dos", "bruteforce", "Benign", "PortScan", "DoS_DDoS", "BruteForce"],
        help="Expected scenario label for this test window",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default="http://localhost:8000",
        help="FastAPI base URL (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="docs/live_eval_results.json",
        help="Output JSON results file path (default: docs/live_eval_results.json)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[list] = None):
    args = parse_args(argv)
    logger.info("Fetching flows between %s and %s...", args.start, args.end)
    flows = fetch_flows_for_window(
        start_time=args.start,
        end_time=args.end,
        api_url=args.api_url,
    )

    if not flows:
        logger.warning("No flows found in the specified window [%s -> %s].", args.start, args.end)

    result = score_scenario(
        flows=flows,
        expected_scenario=args.expected,
        start_time=args.start,
        end_time=args.end,
    )

    print_evaluation_summary(result)
    append_result_to_json(result, output_path=args.output)


if __name__ == "__main__":
    main()
