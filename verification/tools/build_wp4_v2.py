"""Build the final-wp4-v2 batch and report strict-protocol / negative-exclusion results.

Run from the repository root after the 14 raw outputs exist:

    python verification/tools/build_wp4_v2.py
"""
from __future__ import annotations

import csv
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BATCH = ROOT / "results" / "batches" / "wp4-final-wp4-v2"
MANIFEST = ROOT / "prompts" / "prepared" / "final-wp4-v2" / "manifest.json"
GROUND_TRUTH = ROOT / "results" / "batches" / "wp4-poc-01" / "ground_truth.csv"
BASELINE_STRICT = ROOT / "results" / "batches" / "wp4-baseline-final" / "checks" / "static_protocol.json"
V1_STRICT = ROOT / "results" / "batches" / "wp4-final-wp4-v1" / "checks" / "static_protocol.json"
BASELINE_RAW = ROOT / "results" / "batches" / "wp4-baseline-final" / "raw_outputs"
V1_RAW = ROOT / "results" / "batches" / "wp4-final-wp4-v1" / "raw_outputs"
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


def parse_raw(path: Path) -> dict:
    text = path.read_text(encoding="utf-8-sig").strip()
    if text.startswith("```"):
        text = "\n".join(line for line in text.splitlines() if not line.strip().startswith("```")).strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError(f"no JSON object in {path}")
    return json.loads(text[start:end + 1])


def load_truth() -> tuple[dict[str, str], dict[str, str]]:
    labels: dict[str, str] = {}
    evidence: dict[str, str] = {}
    for row in read_csv(GROUND_TRUTH):
        labels.setdefault(row["sample_id"], row["parent_ground_truth"])
        if row.get("main_condition") == "yes" or row["sample_id"] not in evidence:
            evidence[row["sample_id"]] = row["evidence_dir"]
    return labels, evidence


def bundle_hash(manifest: dict, sample: str) -> str:
    hashes = [e["prompt_sha256"] for e in manifest["entries"] if e["sample_id"] == sample]
    return sha256(json.dumps(hashes).encode())


def exclusion_counts(raw_dir: Path) -> dict[str, int]:
    counts = {}
    for path in sorted(raw_dir.glob("*.json")):
        data = parse_raw(path)
        counts[data["sample_id"]] = len(data.get("exclusion_evidence") or [])
    return counts


def main() -> None:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    labels, evidence = load_truth()
    BATCH.mkdir(parents=True, exist_ok=True)
    (BATCH / "structured_outputs").mkdir(exist_ok=True)
    (BATCH / "checks").mkdir(exist_ok=True)

    results = []
    rows = []
    for sample in SAMPLES:
        raw_path = BATCH / "raw_outputs" / f"{sample}.json"
        rel_raw = raw_path.relative_to(ROOT).as_posix()
        rel_struct = (BATCH / "structured_outputs" / f"{sample}.json").relative_to(ROOT).as_posix()
        if not raw_path.exists():
            raise SystemExit(f"missing raw output: {rel_raw}")
        data = parse_raw(raw_path)
        (ROOT / rel_struct).write_text(
            json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
        try:
            check_result = check_outputs.check(data)
            strict = "passed_static_protocol"
            error = ""
        except (ValueError, OSError, SyntaxError, KeyError, TypeError) as exc:
            strict = "failed_static_protocol"
            error = str(exc)
        vtypes = sorted({f.get("vulnerability_type") for f in data.get("findings") or []})
        sc_types = sorted({
            type(((f.get("poc") or {}).get("success_criteria"))).__name__
            for f in data.get("findings") or []
        })
        results.append({
            "sample_id": sample,
            "prompt_version": "final-wp4-v2",
            "file": rel_raw,
            "sha256": sha256(raw_path.read_bytes()),
            "status": strict,
            "error": error,
            "prediction": data.get("prediction"),
            "verdict": data.get("verdict"),
            "finding_count": len(data.get("findings") or []),
            "exclusion_count": len(data.get("exclusion_evidence") or []),
            "vulnerability_types": vtypes,
            "success_criteria_types": sc_types,
        })
        rows.append({
            "sample_id": sample,
            "input_version": "v2",
            "prompt_version": "final-wp4-v2",
            "condition_key": CONDITION,
            "model_name": MODEL_NAME,
            "model_version": MODEL_VERSION,
            "model_parameters": MODEL_PARAMETERS,
            "run_date": RUN_DATE,
            "prompt_bundle_sha256": bundle_hash(manifest, sample),
            "raw_output_path": rel_raw,
            "structured_output_path": rel_struct,
            "prediction": data.get("prediction", ""),
            "location_review": "static_quote_check_passed" if strict == "passed_static_protocol" else "static_quote_check_failed",
            "poc_result": "not_run",
            "ground_truth": labels[sample],
            "validation_evidence": evidence[sample],
            "status": "completed",
            "notes": (
                "independent-context agent run; final-wp4-v2 strict-typing prompt; "
                f"vulnerability_type={','.join(vtypes) or 'none'}; "
                f"success_criteria_type={','.join(sc_types) or 'n/a'}; "
                f"exclusion_evidence={len(data.get('exclusion_evidence') or [])}; "
                f"strict_check={strict}" + (f" ({error})" if error else "")
            ),
        })

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

    passed = sum(r["status"] == "passed_static_protocol" for r in results)
    report = {
        "scope": "Protocol, quote/line consistency, strict type and negative-exclusion count; no model calls or POC execution",
        "output_count": len(results),
        "passed_count": passed,
        "results": results,
    }
    (BATCH / "checks" / "static_protocol.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")

    # Classification metrics (same ground truth as the baseline batch).
    tp = fp = fn = tn = unknown = 0
    for r in results:
        pred, truth = r["prediction"], labels[r["sample_id"]]
        if pred == "无法判定":
            unknown += 1
            continue
        positive_pred, positive_truth = pred == "存在候选", truth == "有漏洞"
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
    accuracy = (tp + tn) / (tp + tn + fp + fn)
    f1 = (2 * precision * recall / (precision + recall)) if precision and recall else None
    metric_rows = [
        ("tp", tp), ("fp", fp), ("fn", fn), ("tn", tn), ("unknown", unknown),
        ("accuracy", "" if accuracy is None else f"{accuracy:.4f}"),
        ("precision", "" if precision is None else f"{precision:.4f}"),
        ("recall", "" if recall is None else f"{recall:.4f}"),
        ("f1", "" if f1 is None else f"{f1:.4f}"),
        ("strict_protocol_passed", passed),
        ("strict_protocol_total", len(results)),
    ]
    with (BATCH / "metrics.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(["metric", "value"])
        writer.writerows(metric_rows)

    baseline = exclusion_counts(BASELINE_RAW)
    v1 = exclusion_counts(V1_RAW)
    v2 = {r["sample_id"]: r["exclusion_count"] for r in results}
    negative_rows = []
    for sample in ("XSS-004", "CMD-004"):
        negative_rows.append({
            "sample_id": sample,
            "baseline_final": baseline.get(sample, 0),
            "final_wp4_v1": v1.get(sample, 0),
            "final_wp4_v2": v2.get(sample, 0),
            "baseline_restored": "yes" if v2.get(sample, 0) >= baseline.get(sample, 0) else "no",
        })
    with (BATCH / "negative_exclusion.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(negative_rows[0].keys()))
        writer.writeheader()
        writer.writerows(negative_rows)

    # Version comparison for the 14 parent samples.
    baseline_rows = {r["sample_id"]: r for r in read_csv(ROOT / "results" / "batches" / "wp4-baseline-final" / "model_runs.csv")}
    v1_rows = {r["sample_id"]: r for r in read_csv(ROOT / "results" / "batches" / "wp4-final-wp4-v1" / "model_runs.csv")}
    v2_by_id = {r["sample_id"]: r for r in rows}
    comparison = []
    for sample in SAMPLES:
        comparison.append({
            "sample_id": sample,
            "ground_truth": labels[sample],
            "baseline_prediction": baseline_rows[sample]["prediction"],
            "v1_prediction": v1_rows[sample]["prediction"],
            "v2_prediction": v2_by_id[sample]["prediction"],
            "baseline_status": baseline_rows[sample]["status"],
            "v1_status": v1_rows[sample]["status"],
            "v2_status": v2_by_id[sample]["status"],
            "v2_vulnerability_types": "; ".join(
                next(r for r in results if r["sample_id"] == sample)["vulnerability_types"]),
            "v2_exclusion_count": v2.get(sample, 0),
        })
    with (BATCH / "comparison.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(comparison[0].keys()))
        writer.writeheader()
        writer.writerows(comparison)

    readme = f"""# wp4-final-wp4-v2：严格协议与负例排除修正批次

- 批次日期：{RUN_DATE}（UTC+08:00）
- 基础：`final-wp4-v1`；输入 v2、14 个父样本、17 个逐包 Prompt 不变
- 改动：仅新增 CR-008 的严格类型与负例排除条款（见 `prompts/prepared/final-wp4-v2/manifest.json`）
- 模型：{MODEL_NAME}；快照/采样参数/用量不可取得
- 保存的是子代理的最终 JSON 响应，不是 token 级流式原文；未在事后修改字段
- 运行提示重复了 Prompt 中已有的 `vulnerability_type` 精确值、字符串类型和负例最小条数规则；这是执行澄清，不是额外漏洞判定信息
- 原始输出：`raw_outputs/`；结构化副本：`structured_outputs/`；严格检查：`checks/static_protocol.json`；CR-008 自动核验：`checks/cr008_verification.json`
- 分类指标：`metrics.csv`；三版对照：`comparison.csv`；负例排除条数：`negative_exclusion.csv`

## 结果

| 指标 | 基线 final | 优化版 final-wp4-v1 | 修正版 final-wp4-v2 |
| --- | --- | --- | --- |
| 分类 TP/FP/FN/TN/U | 12/0/0/2/0 | 12/0/0/2/0 | {tp}/{fp}/{fn}/{tn}/{unknown} |
| 严格静态协议 | 5/14 | 4/14 | {passed}/{len(results)} |
| XSS-004 exclusion_evidence | {baseline.get('XSS-004', 0)} | {v1.get('XSS-004', 0)} | {v2.get('XSS-004', 0)} |
| CMD-004 exclusion_evidence | {baseline.get('CMD-004', 0)} | {v1.get('CMD-004', 0)} | {v2.get('CMD-004', 0)} |

## 限制

- 仍为同一模型家族的子代理辅助批次，不是正式 API 评测，也不是人工独立复核。
- 严格协议通过只证明字段、引用、类型与 Python 语法可机械核验，不证明漏洞判断正确或 POC 可运行。
- 负例排除条数按 `exclusion_evidence` 位置对象计数；数量恢复不等于论证质量自动等价，仍需人工复核内容。
"""
    (BATCH / "README.md").write_text(readme, encoding="utf-8", newline="\n")

    print(json.dumps({
        "records": len(rows),
        "strict_passed": passed,
        "strict_total": len(results),
        "negative_exclusion": negative_rows,
        "metrics": dict(metric_rows),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
