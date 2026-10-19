"""Validate the baseline model batch and build comparison/metrics tables."""
from __future__ import annotations

import csv
import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BATCH = ROOT / "results" / "batches" / "wp4-final-wp4-v1"
RAW = BATCH / "raw_outputs"
STRUCT = BATCH / "structured_outputs"
PROMPTS = ROOT / "prompts" / "prepared" / "final-wp4-v1"

PARENTS = {
    "SQLI-001": ("SQL注入", "有漏洞"),
    "SQLI-002": ("SQL注入", "有漏洞"),
    "SQLI-003": ("SQL注入", "有漏洞"),
    "SQLI-005": ("SQL注入", "有漏洞"),
    "XSS-001": ("XSS", "有漏洞"),
    "XSS-002": ("XSS", "有漏洞"),
    "XSS-003": ("XSS", "有漏洞"),
    "XSS-004": ("XSS", "无所关注漏洞"),
    "XSS-005": ("XSS", "有漏洞"),
    "CMD-001": ("命令注入", "有漏洞"),
    "CMD-002": ("命令注入", "有漏洞"),
    "CMD-003": ("命令注入", "有漏洞"),
    "CMD-004": ("命令注入", "无所关注漏洞"),
    "AUTH-001": ("权限越权", "有漏洞"),
}

PACKETS = {
    "SQLI-005": ["SQLI-005-P1", "SQLI-005-P2"],
    "XSS-005": ["XSS-005-P1"],
    "AUTH-001": ["AUTH-001-P1", "AUTH-001-P2", "AUTH-001-P3"],
}

EVIDENCE_RUN = {
    "SQLI-001": "wp4-20261019-sqli001-low",
    "SQLI-002": "wp4-20261019-sqli002-low",
    "SQLI-003": "wp4-20261019-sqli003-low",
    "SQLI-005": "wp4-20261019-sqli005-low",
    "XSS-001": "wp4-20261019-xss001-low",
    "XSS-002": "wp4-20261019-xss002-medium",
    "XSS-003": "wp4-20261019-xss003-high",
    "XSS-004": "wp4-20261019-xss004-impossible",
    "XSS-005": "wp4-20261019-xss005-low",
    "CMD-001": "wp4-20261019-cmd001-low",
    "CMD-002": "wp4-20261019-cmd002-medium",
    "CMD-003": "wp4-20261019-cmd003-high",
    "CMD-004": "wp4-20261019-cmd004-impossible",
    "AUTH-001": "wp4-20261019-auth001-low",
}


def prompt_files(sample: str) -> list[Path]:
    packets = PACKETS.get(sample)
    if not packets:
        return [PROMPTS / f"{sample}.md"]
    return [PROMPTS / f"{packet}.md" for packet in packets]


def bundle_hash(sample: str) -> str:
    h = hashlib.sha256()
    for path in prompt_files(sample):
        h.update(path.read_bytes())
    return h.hexdigest()


def load_output(sample: str):
    path = RAW / f"{sample}.json"
    if not path.exists():
        return None, ["missing raw output"]
    text = path.read_text(encoding="utf-8")
    text = re.sub(r"^\s*```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```\s*$", "", text)
    try:
        return json.loads(text), []
    except json.JSONDecodeError as exc:
        return None, [f"invalid JSON: {exc}"]


def validate(sample: str, data: dict | None) -> list[str]:
    errors = []
    if not isinstance(data, dict):
        return ["output is not a JSON object"]
    if data.get("schema_version") != "wp2-output-v1":
        errors.append(f"schema_version={data.get('schema_version')!r}")
    if data.get("sample_id") != sample:
        errors.append(f"sample_id={data.get('sample_id')!r}")
    if data.get("input_version") != "v2":
        errors.append(f"input_version={data.get('input_version')!r}")
    if data.get("prompt_version") != "final-wp4-v1":
        errors.append(f"prompt_version={data.get('prompt_version')!r}")
    if data.get("analysis_stage") != "parent":
        errors.append(f"analysis_stage={data.get('analysis_stage')!r}")
    expected = PACKETS.get(sample, [sample])
    got = data.get("received_packet_ids")
    if got != expected:
        errors.append(f"received_packet_ids={got!r}")
    if data.get("prediction") not in ("存在候选", "未检出候选", "无法判定"):
        errors.append(f"prediction={data.get('prediction')!r}")
    if data.get("verdict") not in ("确认", "待验证", "排除"):
        errors.append(f"verdict={data.get('verdict')!r}")
    findings = data.get("findings")
    if not isinstance(findings, list):
        errors.append("findings is not a list")
    else:
        for index, finding in enumerate(findings):
            if not isinstance(finding, dict):
                errors.append(f"finding {index} is not an object")
                continue
            for key in ("finding_id", "vulnerability_type", "locations", "data_flow",
                        "principle", "impact", "preconditions", "counterexamples", "poc"):
                if key not in finding:
                    errors.append(f"finding {index} missing {key}")
            for location in finding.get("locations", []):
                if not location.get("quote"):
                    errors.append(f"finding {index} location without quote")
    return errors


def prediction_binary(data: dict | None) -> str:
    if not isinstance(data, dict):
        return "U"
    if data.get("analysis_stage") != "parent":
        return "U"
    prediction = data.get("prediction")
    if prediction == "存在候选":
        return "1"
    if prediction == "未检出候选":
        return "0"
    return "U"


def path_coverage(sample: str, data: dict | None) -> str:
    if not isinstance(data, dict):
        return "not_available"
    text = json.dumps(data, ensure_ascii=False).lower()
    if sample == "AUTH-001":
        read = ("get_user_data" in text) or ("读取" in text) or ("read" in text)
        update = ("change_user_details" in text) or ("更新" in text) or ("update" in text)
        if read and update:
            return "read+update"
        if update:
            return "update_only"
        if read:
            return "read_only"
        return "unclear"
    if sample == "XSS-005":
        write = ("写入" in text) or ("store" in text) or ("insert" in text)
        read = ("读取" in text) or ("guestbook" in text) or ("read" in text)
        if write and read:
            return "write+read"
        return "partial" if (write or read) else "unclear"
    if sample == "SQLI-005":
        stages = sum(1 for word in ("注册", "登录", "改密", "update") if word in text)
        return "multi_stage" if stages >= 2 else "partial"
    return "single_path"


def main() -> None:
    STRUCT.mkdir(parents=True, exist_ok=True)
    rows = []
    comparisons = []
    failures = []
    tp = fp = fn = tn = u = 0
    compliant = 0
    for sample, (vtype, parent_label) in PARENTS.items():
        data, load_errors = load_output(sample)
        errors = load_errors or validate(sample, data)
        if data is not None and not load_errors:
            STRUCT.joinpath(f"{sample}.json").write_text(
                json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        if not errors:
            compliant += 1
        binary = prediction_binary(data)
        if binary == "1" and parent_label == "有漏洞":
            cls = "TP"
            tp += 1
        elif binary == "1" and parent_label == "无所关注漏洞":
            cls = "FP"
            fp += 1
        elif binary == "0" and parent_label == "有漏洞":
            cls = "FN"
            fn += 1
        elif binary == "0" and parent_label == "无所关注漏洞":
            cls = "TN"
            tn += 1
        else:
            cls = "U"
            u += 1
        status = "completed" if not errors else "format_failed"
        raw_rel = f"results/batches/wp4-final-wp4-v1/raw_outputs/{sample}.json"
        struct_rel = f"results/batches/wp4-final-wp4-v1/structured_outputs/{sample}.json"
        rows.append({
            "sample_id": sample,
            "input_version": "v2",
            "prompt_version": "final-wp4-v1",
            "condition_key": "env=local-lab|role=as-analysed|security=as-analysed|object=none|state=static",
            "model_name": "DeepSeek Harness subagent (deepseek-flash)",
            "model_version": "unknown (server-side snapshot not exposed)",
            "model_parameters": "unknown (sampling parameters not exposed)",
            "run_date": "2026-10-19",
            "prompt_bundle_sha256": bundle_hash(sample),
            "raw_output_path": raw_rel if (RAW / f"{sample}.json").exists() else "",
            "structured_output_path": struct_rel if data is not None else "",
            "prediction": data.get("prediction") if isinstance(data, dict) else "",
            "location_review": "not_reviewed",
            "poc_result": "not_run",
            "ground_truth": parent_label,
            "validation_evidence": f"verification/evidence/{EVIDENCE_RUN[sample]}",
            "status": status,
            "notes": "agent-assisted batch; packets provided together, not incrementally appended; no formal API snapshot",
        })
        comparisons.append({
            "sample_id": sample,
            "vulnerability_type": vtype,
            "parent_ground_truth": parent_label,
            "model_prediction": data.get("prediction") if isinstance(data, dict) else "missing",
            "model_verdict": data.get("verdict") if isinstance(data, dict) else "missing",
            "analysis_stage": data.get("analysis_stage") if isinstance(data, dict) else "missing",
            "binary_prediction": binary,
            "comparison_class": cls,
            "path_coverage": path_coverage(sample, data),
            "format_errors": "; ".join(errors),
            "evidence_dir": f"verification/evidence/{EVIDENCE_RUN[sample]}",
        })
        if cls in ("FP", "FN"):
            findings = data.get("findings", []) if isinstance(data, dict) else []
            failures.append({
                "sample_id": sample,
                "comparison_class": cls,
                "ground_truth": parent_label,
                "model_prediction": data.get("prediction") if isinstance(data, dict) else "",
                "finding_count": len(findings),
                "reason_hint": (
                    "模型在该负例路径报告了候选，但人工运行未取得触发证据；需区分模型判断错误、范围/配置理解错误与POC观测不足。"
                    if cls == "FP" else
                    "人工已在该主条件路径取得触发证据，但模型未检出候选；需检查是否漏掉跨阶段、独立接口或防护分支。"),
                "follow_up": "写入 change_request，按相同条件复测并复核证据。",
            })

    BATCH.mkdir(parents=True, exist_ok=True)
    with open(BATCH / "model_runs.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    with open(BATCH / "comparison.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(comparisons[0].keys()))
        writer.writeheader()
        writer.writerows(comparisons)
    with open(BATCH / "failure_analysis.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "sample_id", "comparison_class", "ground_truth", "model_prediction",
            "finding_count", "reason_hint", "follow_up"])
        writer.writeheader()
        writer.writerows(failures)

    total = tp + fp + fn + tn
    def ratio(num, den):
        return f"{num / den:.4f}" if den else "不适用"
    metrics = [
        ("TP", tp, total, str(tp), "count", "model positive and ground truth positive", "classification"),
        ("FP", fp, total, str(fp), "count", "model positive and ground truth negative", "classification"),
        ("FN", fn, total, str(fn), "count", "model negative and ground truth positive", "classification"),
        ("TN", tn, total, str(tn), "count", "model negative and ground truth negative", "classification"),
        ("U", u, len(PARENTS), str(u), "count", "undetermined, partial or missing", "coverage"),
        ("accuracy", tp + tn, total, ratio(tp + tn, total), "ratio", "(TP+TN)/(TP+TN+FP+FN)", "classification"),
        ("precision", tp, tp + fp, ratio(tp, tp + fp), "ratio", "TP/(TP+FP)", "classification"),
        ("recall", tp, tp + fn, ratio(tp, tp + fn), "ratio", "TP/(TP+FN)", "classification"),
        ("f1", 2 * tp, 2 * tp + fp + fn, ratio(2 * tp, 2 * tp + fp + fn), "ratio", "2TP/(2TP+FP+FN)", "classification"),
        ("false_positive_rate", fp, fp + tn, ratio(fp, fp + tn), "ratio", "FP/(FP+TN)", "classification"),
        ("false_discovery_rate", fp, tp + fp, ratio(fp, tp + fp), "ratio", "FP/(TP+FP)", "classification"),
        ("coverage", total, len(PARENTS), ratio(total, len(PARENTS)), "ratio", "scorable / planned parents", "coverage"),
        ("basic_field_compliance", compliant, len(PARENTS), ratio(compliant, len(PARENTS)), "ratio", "required fields present and raw JSON parses without repair; not the strict quote/type check", "format"),
    ]
    with open(BATCH / "metrics.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(["metric", "numerator", "denominator", "display", "unit", "definition", "category"])
        for row in metrics:
            writer.writerow(row)

    notes = f"""# 模型批次说明（wp4-final-wp4-v1）

## 批次性质

- 模型：DeepSeek Harness 子代理，模型标识 deepseek-flash；服务端快照、采样参数与用量不可取得，记为 unknown。
- 接口：DSH 子代理独立上下文，不是模型 API 的正式调用记录。
- 每个父样本新建上下文；多包样本把 P1/P2(/P3) 一次性提供给同一子代理，未严格模拟逐包追加，比较时需保留这一限制。
- Prompt：`prompts/prepared/final-wp4-v1/` 冻结版本；输入版本 v2；未向模型提供人工标签、POC 证据、难度名或工作包3结论。
- 原始输出保存在 `raw_outputs/`，未做人工修正；`structured_outputs/` 为通过基础字段检查的副本。

## 指标

- 计划父样本 14；可评分 {total}；基础字段合规 {compliant}；U={u}。严格静态协议另由 `check_outputs.py` 检查，不能用本项替代。
- TP={tp}、FP={fp}、FN={fn}、TN={tn}。
- Accuracy={ratio(tp + tn, total)}，Precision={ratio(tp, tp + fp)}，Recall={ratio(tp, tp + fn)}，F1={ratio(2 * tp, 2 * tp + fp + fn)}。
- FPR={ratio(fp, fp + tn)}，FDR={ratio(fp, tp + fp)}。

## 解释限制

- 本批次由与验证执行者同一模型家族生成，且执行者已阅读人工证据；虽然子代理只读取 Prompt，仍不能视为严格独立盲评。
- 样本少、公开靶场、同源难度版本使记忆偏差无法排除。
- `poc_result` 统一为 not_run：模型生成的 POC 未直接执行；实际执行的是人工适配参考 POC，二者不能混算。
- 本批次可用于 WP4 内部对比和发现问题，不用于宣称 Prompt 的泛化提升。
"""
    (BATCH / "metrics_notes.md").write_text(notes, encoding="utf-8")
    print(json.dumps({
        "samples": len(PARENTS),
        "compliant": compliant,
        "TP": tp, "FP": fp, "FN": fn, "TN": tn, "U": u,
        "accuracy": ratio(tp + tn, total),
        "precision": ratio(tp, tp + fp),
        "recall": ratio(tp, tp + fn),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
