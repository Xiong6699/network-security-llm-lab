"""Read-only consistency check for the three completed tasks.

Checks:
1. 42 evaluation records are completed, paths exist and prompt bundles match
   the frozen v1/v2/final manifest;
2. 17 review-log rows carry the blind second-review status and the blind
   comparison has 17/17 trigger and label agreement;
3. final-wp4-v2 has 14/14 strict protocol passes and restores the two negative
   exclusion counts.

Run from the repository root:

    python verification/tools/verify_final_state.py
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EVAL = ROOT / "results" / "batches" / "wp2-eval-42"
V2 = ROOT / "results" / "batches" / "wp4-final-wp4-v2"
POC = ROOT / "results" / "batches" / "wp4-poc-01"
BLIND = ROOT / "verification" / "blind_review"


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def main() -> None:
    errors: list[str] = []
    manifest = json.loads((ROOT / "prompts" / "prepared" / "manifest.json").read_text(encoding="utf-8"))
    records = read_csv(ROOT / "prompts" / "evaluation_records.csv")
    if len(records) != 42:
        errors.append(f"evaluation_records rows={len(records)}")
    for row in records:
        if row["status"] != "completed":
            errors.append(f"{row['sample_id']}/{row['prompt_version']} status={row['status']}")
        for field in ("raw_output_path", "structured_output_path", "validation_evidence"):
            if not (ROOT / row[field]).exists():
                errors.append(f"{row['sample_id']}/{row['prompt_version']} missing {field}")
        hashes = [
            e["prompt_sha256"] for e in manifest["entries"]
            if e["sample_id"] == row["sample_id"] and e["prompt_version"] == row["prompt_version"]
        ]
        bundle = hashlib.sha256(json.dumps(hashes).encode()).hexdigest()
        if row["prompt_bundle_sha256"] != bundle:
            errors.append(f"{row['sample_id']}/{row['prompt_version']} prompt bundle mismatch")

    review = read_csv(POC / "review_log.csv")
    if len(review) != 17:
        errors.append(f"review_log rows={len(review)}")
    for row in review:
        if row["review_status"] != "blind_second_review_completed":
            errors.append(f"{row['run_id']} review_status={row['review_status']}")
        if row["disagreement"] != "none":
            errors.append(f"{row['run_id']} disagreement={row['disagreement']}")

    blind = read_csv(BLIND / "blind_review.csv")
    if len(blind) != 17:
        errors.append(f"blind_review rows={len(blind)}")
    for row in blind:
        if row["trigger_agreement"] != "yes" or row["label_agreement"] != "yes":
            errors.append(f"{row['blind_id']} has disagreement")

    strict = json.loads((V2 / "checks" / "static_protocol.json").read_text(encoding="utf-8"))
    if strict["output_count"] != 14 or strict["passed_count"] != 14:
        errors.append(f"v2 strict={strict['passed_count']}/{strict['output_count']}")
    cr008 = json.loads((V2 / "checks" / "cr008_verification.json").read_text(encoding="utf-8"))
    if cr008["status"] != "passed":
        errors.append(f"CR-008 verification={cr008['status']}")
    for item in cr008["negative_exclusion"]:
        if not item["passed"]:
            errors.append(f"{item['sample_id']} negative exclusion not restored")

    report = {
        "status": "passed" if not errors else "failed",
        "evaluation_records": len(records),
        "review_rows": len(review),
        "blind_rows": len(blind),
        "v2_strict": f"{strict['passed_count']}/{strict['output_count']}",
        "cr008_negative_exclusion": cr008["negative_exclusion"],
        "errors": errors,
    }
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if errors:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
