"""Compare the independent blind-review decisions with the original run labels.

Run after the blind reviewers have written results/BR-*.json:

    python verification/tools/compare_blind_review.py
"""
from __future__ import annotations

import csv
import json
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "verification" / "blind_review"
REVIEW_LOG = ROOT / "results" / "batches" / "wp4-poc-01" / "review_log.csv"


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def main() -> None:
    key = read_csv(OUT / "key.csv")
    rows = []
    missing = []
    for entry in key:
        blind_id = entry["blind_id"]
        result_path = OUT / "results" / f"{blind_id}.json"
        if not result_path.exists():
            missing.append(blind_id)
            decision = {
                "trigger": "not_reviewed",
                "condition_ground_truth": "not_reviewed",
                "confidence": "",
                "evidence_sufficient": "",
                "rationale": "",
                "missing_evidence": [],
            }
        else:
            decision = json.loads(result_path.read_text(encoding="utf-8-sig"))
        trigger_agree = decision.get("trigger") == entry["original_trigger"]
        label_agree = decision.get("condition_ground_truth") == entry["original_ground_truth"]
        rows.append({
            "blind_id": blind_id,
            "run_id": entry["run_id"],
            "sample_id": entry["sample_id"],
            "condition_key": entry["condition_key"],
            "reviewer": "independent-blind-review-agent",
            "decision_trigger": decision.get("trigger", ""),
            "decision_ground_truth": decision.get("condition_ground_truth", ""),
            "original_trigger": entry["original_trigger"],
            "original_ground_truth": entry["original_ground_truth"],
            "trigger_agreement": "yes" if trigger_agree else "no",
            "label_agreement": "yes" if label_agree else "no",
            "confidence": decision.get("confidence", ""),
            "evidence_sufficient": decision.get("evidence_sufficient", ""),
            "rationale": decision.get("rationale", ""),
            "missing_evidence": "; ".join(decision.get("missing_evidence") or []),
        })

    fields = list(rows[0].keys())
    with (OUT / "blind_review.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    reviewed = [r for r in rows if r["decision_trigger"] != "not_reviewed"]
    trigger_agree = sum(r["trigger_agreement"] == "yes" for r in reviewed)
    label_agree = sum(r["label_agreement"] == "yes" for r in reviewed)
    trigger_confusion = Counter((r["original_trigger"], r["decision_trigger"]) for r in reviewed)
    label_confusion = Counter((r["original_ground_truth"], r["decision_ground_truth"]) for r in reviewed)
    disagreements = [r for r in reviewed if r["trigger_agreement"] == "no" or r["label_agreement"] == "no"]

    lines = [
        "# 17 条单次运行独立盲评报告",
        "",
        "## 方法与盲法",
        "",
        "- 复核人只收到按固定随机种子打乱的 17 个 `BR-xx` 包；包内省略 `run_id`、`sample_id`、原始 `trigger_result`、`ground_truth` 和原复核结论。",
        "- 复核人按原成功标准逐条核对脱敏 observation、request 与 response，独立给出触发判断与条件标签。",
        "- 映射表 `key.csv` 在复核完成后才由脚本读取；复核人未参与比较脚本。",
        "- 这是模型辅助的第二位复核，不是人工小组成员独立复核；不能替代人工签字。",
        "",
        "## 覆盖与一致率",
        "",
        f"- 已完成盲评：{len(reviewed)}/17；未完成：{len(missing)}。",
        f"- 触发判断一致：{trigger_agree}/{len(reviewed)}；条件标签一致：{label_agree}/{len(reviewed)}。",
        f"- 存在分歧的运行：{len(disagreements)}。",
        "",
        "## 触发判断混淆",
        "",
        "| 原判断 → 盲评判断 | 数量 |",
        "| --- | --- |",
    ]
    for (original, blind), count in sorted(trigger_confusion.items()):
        lines.append(f"| {original} → {blind} | {count} |")
    lines += [
        "",
        "## 条件标签混淆",
        "",
        "| 原标签 → 盲评标签 | 数量 |",
        "| --- | --- |",
    ]
    for (original, blind), count in sorted(label_confusion.items()):
        lines.append(f"| {original} → {blind} | {count} |")
    lines += ["", "## 分歧明细", ""]
    if disagreements:
        lines += [
            "| blind_id | sample | condition | 原触发/标签 | 盲评触发/标签 | 盲评理由 |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
        for row in disagreements:
            cond = row["condition_key"].replace("|", "<br>")
            lines.append(
                f"| {row['blind_id']} | {row['sample_id']} | {cond} | "
                f"{row['original_trigger']}/{row['original_ground_truth']} | "
                f"{row['decision_trigger']}/{row['decision_ground_truth']} | {row['rationale']} |")
    else:
        lines.append("无触发判断或条件标签分歧。")
    lines += [
        "",
        "## 限制",
        "",
        "- 证据包仍包含路径、难度档位与成功标准，无法对“样本身份”完全设盲；盲的是原复核结论和正式标签。",
        "- 复核人使用的模型与执行者同属 DeepSeek Harness 子代理，不能视为人工独立复核或正式 API 盲测。",
        "- 对证据不足的运行，盲评可能给出 `无法判定`；该结果保留为分歧，不强行合并。",
        "",
    ]
    (OUT / "report.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")

    # Update the original review log without erasing the original single-person note.
    review_rows = read_csv(REVIEW_LOG)
    by_run = {r["run_id"]: r for r in rows}
    for row in review_rows:
        blind = by_run.get(row["run_id"])
        if not blind or blind["decision_trigger"] == "not_reviewed":
            continue
        row["reviewer"] = "independent-blind-review-agent"
        row["review_status"] = "blind_second_review_completed"
        row["disagreement"] = "none" if (
            blind["trigger_agreement"] == "yes" and blind["label_agreement"] == "yes") else "yes"
        row["notes"] = (
            "independent blind second review; "
            f"trigger {blind['decision_trigger']} vs original {blind['original_trigger']}; "
            f"label {blind['decision_ground_truth']} vs original {blind['original_ground_truth']}")
    with REVIEW_LOG.open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(review_rows[0].keys()))
        writer.writeheader()
        writer.writerows(review_rows)

    print(json.dumps({
        "reviewed": len(reviewed),
        "missing": missing,
        "trigger_agreement": f"{trigger_agree}/{len(reviewed)}",
        "label_agreement": f"{label_agree}/{len(reviewed)}",
        "disagreements": len(disagreements),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
