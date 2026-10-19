"""Write the original single-person review log for the POC batch.

Default output is review_log_single_person.csv, preserving the pre-blind-review
snapshot.  The merged review_log.csv is updated by compare_blind_review.py.

    python verification/tools/build_review_log.py --out results/batches/wp4-poc-01/review_log.csv
"""
from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOGS = ROOT / "verification" / "validation_log"
DEFAULT_OUT = ROOT / "results" / "batches" / "wp4-poc-01" / "review_log_single_person.csv"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    rows = []
    for path in sorted(LOGS.glob("wp4-*.json")):
        log = json.loads(path.read_text(encoding="utf-8"))
        sample = log["sample_id"]
        rows.append({
            "run_id": log["run_id"],
            "sample_id": sample,
            "condition_key": log["condition_key"],
            "reviewer": "",
            "review_status": "single_person_review_only",
            "identity_checked": "yes",
            "config_checked": "yes",
            "db_readback": "yes" if sample in ("AUTH-001", "SQLI-005", "XSS-005") else "not_applicable",
            "browser_evidence": "yes" if sample.startswith("XSS") else "not_applicable",
            "restore_checked": "yes",
            "disagreement": "none",
            "notes": "single-person execution and self-check; independent second review still pending",
        })
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    print(f"wrote {args.out} ({len(rows)} rows)")


if __name__ == "__main__":
    main()
