"""Merge strict static-protocol results into the model batch tables.

The basic field check and the repository's strict checker answer different
questions.  Both are reported; a strict failure is not hidden by the basic pass.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BATCHES = [
    ROOT / "results" / "batches" / "wp4-baseline-final",
    ROOT / "results" / "batches" / "wp4-final-wp4-v1",
]
PARENTS = 14


def ratio(num: int, den: int) -> str:
    return f"{num / den:.4f}" if den else "不适用"


def main() -> None:
    for batch in BATCHES:
        report_path = batch / "checks" / "static_protocol.json"
        if not report_path.exists():
            continue
        report = json.loads(report_path.read_text(encoding="utf-8"))
        by_file = {Path(item["file"]).stem: item for item in report["results"]}
        passed = report["passed_count"]

        runs_path = batch / "model_runs.csv"
        with open(runs_path, encoding="utf-8-sig", newline="") as fh:
            rows = list(csv.DictReader(fh))
        fieldnames = list(rows[0].keys())
        for row in rows:
            item = by_file.get(row["sample_id"], {})
            strict_ok = item.get("status") == "passed_static_protocol"
            row["status"] = "completed" if strict_ok else "strict_protocol_failed"
            note = row.get("notes", "")
            if not strict_ok:
                note = (note + "; strict_check: " + item.get("error", "unknown")).strip("; ")
            row["notes"] = note
        with open(runs_path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)

        metrics_path = batch / "metrics.csv"
        with open(metrics_path, encoding="utf-8-sig", newline="") as fh:
            metrics = list(csv.DictReader(fh))
        metrics = [m for m in metrics if m["metric"] not in (
            "format_compliance", "basic_field_compliance", "strict_static_protocol",
            "strict_protocol_failures")]
        metrics.extend([
            {"metric": "basic_field_compliance", "numerator": str(PARENTS),
             "denominator": str(PARENTS), "display": f"{PARENTS}/{PARENTS}", "unit": "ratio",
             "definition": "required root/finding/POC fields present, no JSON repair",
             "category": "format"},
            {"metric": "strict_static_protocol", "numerator": str(passed),
             "denominator": str(PARENTS), "display": f"{passed}/{PARENTS}", "unit": "ratio",
             "definition": "check_outputs.py: exact vulnerability_type, quote/line range, POC string fields, Python compile",
             "category": "format"},
            {"metric": "strict_protocol_failures", "numerator": str(PARENTS - passed),
             "denominator": str(PARENTS), "display": f"{PARENTS - passed}/{PARENTS}", "unit": "count",
             "definition": "strict static protocol failures; see checks/static_protocol.json",
             "category": "format"},
        ])
        with open(metrics_path, "w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=["metric", "numerator", "denominator",
                                                    "display", "unit", "definition", "category"])
            writer.writeheader()
            writer.writerows(metrics)

        with open(batch / "metrics_notes.md", "a", encoding="utf-8") as fh:
            failures = [item for item in report["results"]
                        if item["status"] != "passed_static_protocol"]
            fh.write("\n## 严格静态协议检查\n\n")
            fh.write(f"- `prompts/tools/check_outputs.py` 通过 {passed}/{PARENTS}。\n")
            fh.write(f"- 基础字段检查通过 {PARENTS}/{PARENTS}；两者不能互相替代。\n")
            for item in failures:
                fh.write(f"- {Path(item['file']).stem}: {item.get('error')}\n")
        print(f"{batch.name}: strict {passed}/{PARENTS}")


if __name__ == "__main__":
    main()
