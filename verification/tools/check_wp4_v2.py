"""Verify the CR-008 fix on the final-wp4-v2 batch.

Checks:
1. every raw output passes check_outputs.py (strict types, exact
   vulnerability_type, quote/line consistency, Python syntax);
2. XSS-004 and CMD-004 exclusion_evidence counts are at least the baseline
   counts (4 and 7) and at least the final-wp4-v1 counts.

Run from the repository root:

    python verification/tools/check_wp4_v2.py
"""
from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BATCH = ROOT / "results" / "batches" / "wp4-final-wp4-v2"
BASELINE = ROOT / "results" / "batches" / "wp4-baseline-final" / "raw_outputs"
V1 = ROOT / "results" / "batches" / "wp4-final-wp4-v1" / "raw_outputs"
sys.path.insert(0, str(ROOT / "prompts" / "tools"))
import check_outputs  # noqa: E402


def load(path: Path) -> dict:
    text = path.read_text(encoding="utf-8-sig").strip()
    if text.startswith("```"):
        text = "\n".join(line for line in text.splitlines() if not line.strip().startswith("```")).strip()
    return json.loads(text[text.find("{"):text.rfind("}") + 1])


def exclusion_count(path: Path, sample: str) -> int:
    return len(load(path / f"{sample}.json").get("exclusion_evidence") or [])


def main() -> None:
    failures = []
    for path in sorted((BATCH / "raw_outputs").glob("*.json")):
        data = load(path)
        try:
            check_outputs.check(data)
        except Exception as exc:  # noqa: BLE001 - report every failure verbatim
            failures.append({"file": path.name, "error": str(exc)})
    comparisons = []
    for sample, baseline_min in (("XSS-004", 4), ("CMD-004", 7)):
        baseline = exclusion_count(BASELINE, sample)
        v1 = exclusion_count(V1, sample)
        v2 = exclusion_count(BATCH / "raw_outputs", sample)
        comparisons.append({
            "sample_id": sample,
            "baseline_final": baseline,
            "final_wp4_v1": v1,
            "final_wp4_v2": v2,
            "baseline_minimum": baseline_min,
            "passed": v2 >= baseline_min and v2 >= baseline and v2 >= v1,
        })
    report = {
        "batch": "wp4-final-wp4-v2",
        "strict_protocol_passed": 14 - len(failures),
        "strict_protocol_total": 14,
        "failures": failures,
        "negative_exclusion": comparisons,
        "status": "passed" if not failures and all(c["passed"] for c in comparisons) else "failed",
    }
    out = BATCH / "checks" / "cr008_verification.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
