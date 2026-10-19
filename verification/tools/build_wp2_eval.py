"""Build the 42-record v1/v2/final evaluation batch and fill evaluation_records.csv.

Inputs are one raw JSON response per sample and prompt version, written by an
independent-context agent run.  Raw outputs are never edited; structured copies
are a byte-for-byte semantic copy saved with stable formatting.

Run from the repository root:

    python verification/tools/build_wp2_eval.py
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BATCH = ROOT / "results" / "batches" / "wp2-eval-42"
MANIFEST = ROOT / "prompts" / "prepared" / "manifest.json"
RECORDS = ROOT / "prompts" / "evaluation_records.csv"
GROUND_TRUTH = ROOT / "results" / "batches" / "wp4-poc-01" / "ground_truth.csv"
VERSIONS = ("v1", "v2", "final")
SAMPLES = (
    "SQLI-001", "SQLI-002", "SQLI-003", "SQLI-005",
    "XSS-001", "XSS-002", "XSS-003", "XSS-004", "XSS-005",
    "CMD-001", "CMD-002", "CMD-003", "CMD-004", "AUTH-001",
)
MODEL_NAME = "DeepSeek Harness subagent (deepseek-flash)"
MODEL_VERSION = "unknown (server-side snapshot not exposed)"
MODEL_PARAMETERS = "unknown (sampling parameters not exposed)"
RUN_DATE = "2026-10-19"
CONDITION = "env=local-lab|role=as-analysed|security=as-analysed|object=none|state=static"

sys.path.insert(0, str(ROOT / "prompts" / "tools"))
import check_outputs  # noqa: E402


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_csv(path: Path) -> list[dict]:
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def bundle_hash(manifest: dict, sample: str, version: str) -> str:
    hashes = [e["prompt_sha256"] for e in manifest["entries"]
              if e["sample_id"] == sample and e["prompt_version"] == version]
    if not hashes:
        raise ValueError(f"no prompt entries for {sample}/{version}")
    return sha256(json.dumps(hashes).encode())


def parse_raw(path: Path) -> dict:
    text = path.read_text(encoding="utf-8-sig").strip()
    if text.startswith("```"):
        lines = [line for line in text.splitlines() if not line.strip().startswith("```")]
        text = "\n".join(lines).strip()
    start = text.find("{")
    end = text.rfind("}")
    if start < 0 or end < start:
        raise ValueError(f"no JSON object in {path}")
    return json.loads(text[start:end + 1])


def load_ground_truth() -> tuple[dict[str, str], dict[str, str]]:
    rows = read_csv(GROUND_TRUTH)
    labels: dict[str, str] = {}
    evidence: dict[str, str] = {}
    for row in rows:
        sid = row["sample_id"]
        labels.setdefault(sid, row["parent_ground_truth"])
        if row.get("main_condition") == "yes" or sid not in evidence:
            evidence[sid] = row["evidence_dir"]
    return labels, evidence


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--update-records", action="store_true")
    args = parser.parse_args()

    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    labels, evidence = load_ground_truth()
    BATCH.mkdir(parents=True, exist_ok=True)
    (BATCH / "structured_outputs").mkdir(exist_ok=True)
    (BATCH / "checks").mkdir(exist_ok=True)

    rows = []
    results = []
    missing = []
    for version in VERSIONS:
        for sample in SAMPLES:
            raw_path = BATCH / "raw_outputs" / f"{sample}__{version}.json"
            rel_raw = raw_path.relative_to(ROOT).as_posix()
            rel_struct = (BATCH / "structured_outputs" / f"{sample}__{version}.json").relative_to(ROOT).as_posix()
            if not raw_path.exists():
                missing.append(rel_raw)
                continue
            data = parse_raw(raw_path)
            structured_path = ROOT / rel_struct
            structured_path.write_text(
                json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
            try:
                check_result = check_outputs.check(data)
                strict_status = "passed_static_protocol"
                strict_error = ""
            except (ValueError, OSError, SyntaxError, KeyError, TypeError) as exc:
                strict_status = "failed_static_protocol"
                strict_error = str(exc)
            results.append({
                "sample_id": sample,
                "prompt_version": version,
                "file": rel_raw,
                "sha256": sha256(raw_path.read_bytes()),
                "status": strict_status,
                "error": strict_error,
                "prediction": data.get("prediction"),
                "verdict": data.get("verdict"),
                "finding_count": len(data.get("findings") or []),
                "exclusion_count": len(data.get("exclusion_evidence") or []),
            })
            note = (
                "independent-context agent run; prepared prompt used verbatim; "
                "runner note clarified that location line numbers are local to the code block; "
                "multi-packet samples received all packets in one context, not incrementally appended; "
                "no formal API snapshot; "
                f"strict_check={strict_status}" + (f" ({strict_error})" if strict_error else "")
            )
            rows.append({
                "sample_id": sample,
                "input_version": "v2",
                "prompt_version": version,
                "condition_key": CONDITION,
                "model_name": MODEL_NAME,
                "model_version": MODEL_VERSION,
                "model_parameters": MODEL_PARAMETERS,
                "run_date": RUN_DATE,
                "prompt_bundle_sha256": bundle_hash(manifest, sample, version),
                "raw_output_path": rel_raw,
                "structured_output_path": rel_struct,
                "prediction": data.get("prediction", ""),
                "location_review": "static_quote_check_passed" if strict_status == "passed_static_protocol" else "static_quote_check_failed",
                "poc_result": "not_run",
                "ground_truth": labels[sample],
                "validation_evidence": evidence[sample],
                "status": "completed",
                "notes": note,
            })

    if missing:
        raise SystemExit("Missing raw outputs:\n" + "\n".join(missing))

    # Batch-level model_runs.csv
    fields = [
        "sample_id", "input_version", "prompt_version", "condition_key", "model_name",
        "model_version", "model_parameters", "run_date", "prompt_bundle_sha256",
        "raw_output_path", "structured_output_path", "prediction", "location_review",
        "poc_result", "ground_truth", "validation_evidence", "status", "notes",
    ]
    with (BATCH / "model_runs.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)

    # Strict protocol reports per version and combined.
    for version in VERSIONS:
        subset = [r for r in results if r["prompt_version"] == version]
        report = {
            "scope": "Protocol, quote/line consistency and Python compilation only; no model calls or POC execution",
            "output_count": len(subset),
            "passed_count": sum(r["status"] == "passed_static_protocol" for r in subset),
            "results": subset,
        }
        (BATCH / "checks" / f"static_protocol_{version}.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    combined = {
        "scope": "Protocol, quote/line consistency and Python compilation only; no model calls or POC execution",
        "output_count": len(results),
        "passed_count": sum(r["status"] == "passed_static_protocol" for r in results),
        "results": results,
    }
    (BATCH / "checks" / "static_protocol.json").write_text(
        json.dumps(combined, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

    # Metrics per prompt version.
    metric_rows = []
    for version in VERSIONS:
        subset = [r for r in results if r["prompt_version"] == version]
        tp = fp = fn = tn = unknown = 0
        for r in subset:
            pred = r["prediction"]
            truth = labels[r["sample_id"]]
            if pred == "无法判定":
                unknown += 1
                continue
            positive_pred = pred == "存在候选"
            positive_truth = truth == "有漏洞"
            if positive_pred and positive_truth:
                tp += 1
            elif positive_pred and not positive_truth:
                fp += 1
            elif not positive_pred and positive_truth:
                fn += 1
            else:
                tn += 1
        precision = tp / (tp + fp) if tp + fp else None
        recall = tp / (tp + fn) if tp + fn else None
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else None
        f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
        metric_rows.append({
            "prompt_version": version,
            "n": len(subset),
            "tp": tp, "fp": fp, "fn": fn, "tn": tn, "unknown": unknown,
            "accuracy": "" if accuracy is None else f"{accuracy:.4f}",
            "precision": "" if precision is None else f"{precision:.4f}",
            "recall": "" if recall is None else f"{recall:.4f}",
            "f1": "" if f1 is None else f"{f1:.4f}",
            "strict_protocol_passed": sum(r["status"] == "passed_static_protocol" for r in subset),
            "strict_protocol_total": len(subset),
        })
    with (BATCH / "metrics.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(metric_rows[0].keys()))
        writer.writeheader()
        writer.writerows(metric_rows)

    # Per-sample comparison across versions.
    by_key = {(r["sample_id"], r["prompt_version"]): r for r in results}
    comparison = []
    for sample in SAMPLES:
        row = {"sample_id": sample, "ground_truth": labels[sample]}
        for version in VERSIONS:
            r = by_key[(sample, version)]
            row[f"{version}_prediction"] = r["prediction"]
            row[f"{version}_strict"] = r["status"]
            row[f"{version}_findings"] = r["finding_count"]
            row[f"{version}_exclusion"] = r["exclusion_count"]
        comparison.append(row)
    with (BATCH / "comparison.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(comparison[0].keys()))
        writer.writeheader()
        writer.writerows(comparison)

    # README
    readme = f"""# wp2-eval-42：v1/v2/final 42 条运行批次（子代理辅助）

- 批次日期：{RUN_DATE}（UTC+08:00）
- 输入：工作包1 v2；Prompt：`prompts/prepared/{{v1,v2,final}}/`（逐字使用）
- 样本：14 个父样本 × 3 个 Prompt 版本 = 42 条记录
- 模型：{MODEL_NAME}；模型快照、采样参数与用量不可取得，记为 unknown
- 运行方式：每条记录一个独立子代理上下文；多包样本（SQLI-005、XSS-005、AUTH-001）把同一父样本的全部包放在同一上下文一次提供，未严格逐包追加。
- 运行提示：仅补充“位置行号取代码块内 1 起始行号”的操作说明；未修改审计 Prompt 内容、样本或判定门槛。
- 保存的是子代理的最终 JSON 响应，不是 token 级流式原文；未在事后修改字段。
- 原始输出：`raw_outputs/<sample>__<version>.json`；结构化副本：`structured_outputs/`
- 严格检查：`checks/static_protocol.json` 与分版本报告
- 指标：`metrics.csv`；说明：`metrics_notes.md`；逐样本对照：`comparison.csv`
- 正式表：`prompts/evaluation_records.csv` 的 42 条记录已填为 `completed`
- 运行协议与偏差：`run_protocol.md`
- 预试验：`attempts/` 保留 1 次行号误用的试跑，不计入 42 条

## 指标

| 版本 | n | TP/FP/FN/TN/U | Accuracy | Precision | Recall | F1 | 严格协议 |
| --- | --- | --- | --- | --- | --- | --- | --- |
"""
    for m in metric_rows:
        readme += (
            f"| {m['prompt_version']} | {m['n']} | {m['tp']}/{m['fp']}/{m['fn']}/{m['tn']}/{m['unknown']} | "
            f"{m['accuracy'] or '不适用'} | {m['precision'] or '不适用'} | {m['recall'] or '不适用'} | "
            f"{m['f1'] or '不适用'} | {m['strict_protocol_passed']}/{m['strict_protocol_total']} |\n")
    readme += """
## 限制

- 不是正式 API 评测：模型服务端快照、采样参数和用量不可取得，不能与商业 API 结果等同。
- 子代理与人工验证执行者同属一个模型家族，且执行者已接触人工证据；本批次不是独立人工盲评。
- 多包样本一次性提供，不等同于严格逐包追加；该偏差在每条记录 notes 中注明。
- 公开靶场、14 个父样本的小样本结果不能外推真实业务系统。
- 模型 POC 未执行，`poc_result=not_run`；严格静态协议通过只说明字段、引用和 Python 语法可机械核验。
- 严格协议失败按原样保留，不修改原始输出换取通过；42 条中 25 条失败：23 条为 `vulnerability_type` 带括号/子类型（如 `XSS（反射型）`、`SQL注入（二阶）`），2 条为 `limitations` 不是字符串数组。修复版本见 `prompts/prepared/final-wp4-v2/` 与 `results/batches/wp4-final-wp4-v2/`。
"""
    (BATCH / "README.md").write_text(readme, encoding="utf-8", newline="\n")

    if args.update_records:
        records = read_csv(RECORDS)
        index = {(r["sample_id"], r["prompt_version"]): r for r in records}
        for row in rows:
            target = index[(row["sample_id"], row["prompt_version"])]
            if target["prompt_bundle_sha256"] != row["prompt_bundle_sha256"]:
                raise ValueError(
                    f"prompt bundle mismatch for {row['sample_id']}/{row['prompt_version']}: "
                    f"{target['prompt_bundle_sha256']} != {row['prompt_bundle_sha256']}")
            target.update(row)
        with RECORDS.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(records[0].keys()), lineterminator="\n")
            writer.writeheader()
            writer.writerows(records)

    print(json.dumps({
        "records": len(rows),
        "strict_passed": combined["passed_count"],
        "strict_total": combined["output_count"],
        "metrics": metric_rows,
        "records_updated": bool(args.update_records),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
