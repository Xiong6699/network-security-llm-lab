"""Compare the baseline final batch with the final-wp4-v1 batch.

Classification is expected to stay unchanged on this small set; the primary
comparison is the POC runtime-evidence contract, which was the change target.
"""
from __future__ import annotations

import csv
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / "results" / "batches" / "wp4-baseline-final"
VAR = ROOT / "results" / "batches" / "wp4-final-wp4-v1"


def read_rows(path: Path) -> list[dict]:
    with open(path, encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def poc_text(sample: str, batch: Path) -> str:
    path = batch / "raw_outputs" / f"{sample}.json"
    if not path.exists():
        return ""
    data = json.loads(path.read_text(encoding="utf-8"))
    chunks = []
    for finding in data.get("findings", []):
        poc = finding.get("poc") or {}
        for key in ("parameters", "steps", "expected_observation", "success_criteria", "limitations"):
            value = poc.get(key)
            if isinstance(value, list):
                chunks.extend(str(item) for item in value)
            elif value:
                chunks.append(str(value))
    return "\n".join(chunks).lower()


def batch_output(sample: str, batch: Path) -> dict:
    path = batch / "raw_outputs" / f"{sample}.json"
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def contract_score(sample: str, batch: Path) -> tuple[int, int, dict, int]:
    data = batch_output(sample, batch)
    exclusion_count = len(data.get("exclusion_evidence", []))
    if data.get("prediction") == "未检出候选":
        # A negative sample is expected to provide exclusion evidence, not an attack POC.
        return 0, 0, {"negative_no_poc": True}, exclusion_count
    text = poc_text(sample, batch)
    checks = {}
    checks["result_region"] = any(word in text for word in (
        "结果区域", "业务结果", "login_name", "your login name", "json", "字段", "提取", "解析", "回读"))
    checks["exact_parameters"] = any(word in text for word in (
        "--param", "--page-path", "参数名", "user_token", "uname", "passwd", "name=", "--path"))
    checks["token_freshness"] = any(word in text for word in ("最新", "token", "同会话", "重新获取"))
    checks["independent_readback"] = any(word in text for word in (
        "回查", "回读", "独立", "恢复", "定向"))
    checks["client_limit"] = any(word in text for word in ("maxlength", "50", "长度", "截断"))
    checks["output_semantics"] = any(word in text for word in (
        "命令输出", "<pre>", "空行", "假条件", "语法错误", "反射"))
    checks["success_explicit"] = len(text) > 600
    applicable = {
        "result_region": True,
        "exact_parameters": True,
        "token_freshness": sample in ("XSS-004", "CMD-004"),
        "independent_readback": sample in ("AUTH-001", "XSS-005", "SQLI-005"),
        "client_limit": sample == "XSS-005",
        "output_semantics": sample.startswith(("SQLI", "CMD")),
        "success_explicit": True,
    }
    score = sum(1 for key, value in checks.items() if applicable[key] and value)
    total = sum(1 for value in applicable.values() if value)
    return score, total, checks, exclusion_count


def main() -> None:
    base_rows = {row["sample_id"]: row for row in read_rows(BASE / "comparison.csv")}
    var_rows = {row["sample_id"]: row for row in read_rows(VAR / "comparison.csv")}
    table = []
    base_total_score = var_total_score = 0
    base_total_max = var_total_max = 0
    for sample in sorted(base_rows):
        b = base_rows[sample]
        v = var_rows.get(sample)
        b_score, b_max, b_checks, b_excl = contract_score(sample, BASE)
        v_score, v_max, v_checks, v_excl = contract_score(sample, VAR)
        base_total_score += b_score
        var_total_score += v_score
        base_total_max += b_max
        var_total_max += v_max
        b_display = f"{b_score}/{b_max}" if b_max else "n/a"
        v_display = f"{v_score}/{v_max}" if v_max else "n/a"
        table.append({
            "sample_id": sample,
            "baseline_prediction": b["model_prediction"],
            "variant_prediction": v["model_prediction"] if v else "missing",
            "baseline_class": b["comparison_class"],
            "variant_class": v["comparison_class"] if v else "U",
            "class_change": "same" if v and b["comparison_class"] == v["comparison_class"] else "changed",
            "baseline_poc_score": b_display,
            "variant_poc_score": v_display,
            "delta": v_score - b_score,
            "baseline_exclusion_evidence": b_excl,
            "variant_exclusion_evidence": v_excl,
            "baseline_checks": b_checks,
            "variant_checks": v_checks,
            "path_coverage_baseline": b["path_coverage"],
            "path_coverage_variant": v["path_coverage"] if v else "missing",
        })

    with open(VAR / "version_comparison.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "sample_id", "baseline_prediction", "variant_prediction",
            "baseline_class", "variant_class", "class_change",
            "baseline_poc_score", "variant_poc_score", "delta",
            "baseline_exclusion_evidence", "variant_exclusion_evidence",
            "path_coverage_baseline", "path_coverage_variant",
        ])
        for row in table:
            writer.writerow([
                row["sample_id"], row["baseline_prediction"], row["variant_prediction"],
                row["baseline_class"], row["variant_class"], row["class_change"],
                row["baseline_poc_score"], row["variant_poc_score"], row["delta"],
                row["baseline_exclusion_evidence"], row["variant_exclusion_evidence"],
                row["path_coverage_baseline"], row["path_coverage_variant"],
            ])

    changed = [row for row in table if row["class_change"] != "same"]
    improved = [row for row in table if row["delta"] > 0]
    regressed = [row for row in table if row["delta"] < 0]
    report = f"""# 工作包4 优化复测报告（final → final-wp4-v1）

批次：`wp4-baseline-final` → `wp4-final-wp4-v1`  
日期：2026-10-19（UTC+08:00）  
输入：v2，不变；样本：14 个父样本，不变；模型与调用方式：DeepSeek Harness 子代理，不变。

## 1. 改动依据

基线分类结果为 14/14，没有 FP/FN，因此本轮不以“提高准确率”为目标。改动依据来自 POC 适配与观测中实际出现的问题（见 `results/change_requests.csv`）：

| change_id | 问题 | 证据 | 改动 |
| --- | --- | --- | --- |
| CR-001 | SQL POC 只报告状态/长度/哈希 | SQLI-001 适配记录 | success_criteria 必须解析业务结果区域，并做真/假/报错对照 |
| CR-002 | XSS POC 只报告反射 | XSS-001 浏览器证据 | 必须给出浏览器/DOM 执行证据，并与反射分开 |
| CR-003 | AUTH POC 只测读取 | AUTH-001 四档矩阵 | 页面/读取/更新分别判断；写操作有原值、独立回查和恢复 |
| CR-004 | Token 复用/拒绝被当作防护 | XSS-004、CMD-004 | 同会话按请求取最新 Token，失败分类为认证前置条件 |
| CR-005 | 存储 payload 超过 maxlength=50 | XSS-005 首次浏览器失败 | 适配字段长度，并在 limitations 说明 |
| CR-006 | 命令标记只在整页响应中查找 | CMD-001 | 必须解析命令输出区域并排除反射 |
| CR-007 | 二阶注入缺少多阶段流程 | SQLI-005 | 逐阶段记录会话/数据库回查和定向清理 |

`final-wp4-v1` 新增“POC 运行证据补充要求”7 条；未修改被审计代码、包顺序、输入版本或判定门槛。

## 2. 分类对比

- 基线：TP=12、FP=0、FN=0、TN=2，Accuracy=1.0000。
- 优化版：见 `results/batches/wp4-final-wp4-v1/metrics.csv`。
- 分类发生变化的样本：{len(changed)} 个。
- 分类提升：{len([r for r in table if r['delta'] > 0 and r['variant_class'] != r['baseline_class']])} 个；分类退步：{len([r for r in table if r['delta'] < 0 and r['variant_class'] != r['baseline_class']])} 个。

由于基线已无分类错误，本轮**不宣称** Prompt 优化提升了准确率；报告的是 POC 证据契约的变化，而不是漏洞判断准确率的变化。

严格静态协议检查（`prompts/tools/check_outputs.py`）：基线 5/14，优化版 4/14。主要失败是 `vulnerability_type` 使用带括号的子类型（如“XSS（反射型）”“SQL注入（二阶）”），不符合检查器要求的精确 `audit_scope`；优化版 CMD-003 还把 `success_criteria` 写成数组，新增一条类型错误。这是格式维度的真实退步，不能因为 POC 契约提升而忽略。

## 3. POC 证据契约评分

评分是对 `success_criteria`/`steps`/`parameters`/`limitations` 的关键词与完整性启发式检查，满分 7 项（按样本适用项裁剪），不是人工质量评分，也不代表实际执行成功。

| sample_id | 基线 | 优化版 | Δ | 路径覆盖（基线→优化） |
| --- | --- | --- | --- | --- |
"""
    for row in table:
        report += (f"| {row['sample_id']} | {row['baseline_poc_score']} | "
                   f"{row['variant_poc_score']} | {row['delta']:+d} | "
                   f"{row['path_coverage_baseline']}→{row['path_coverage_variant']} |\n")
    report += f"""
合计：基线 {base_total_score}/{base_total_max}，优化版 {var_total_score}/{var_total_max}。
提升样本 {len(improved)} 个，退步样本 {len(regressed)} 个，不变 {len(table) - len(improved) - len(regressed)} 个（其中 2 个负例为 n/a；正例中提升 5、不变 7）。

负例 XSS-004、CMD-004 不要求攻击 POC，POC 契约评分记为 n/a；它们改为记录排除证据条数（基线/优化版）：XSS-004 {next(r['baseline_exclusion_evidence'] for r in table if r['sample_id']=='XSS-004')}/{next(r['variant_exclusion_evidence'] for r in table if r['sample_id']=='XSS-004')}，CMD-004 {next(r['baseline_exclusion_evidence'] for r in table if r['sample_id']=='CMD-004')}/{next(r['variant_exclusion_evidence'] for r in table if r['sample_id']=='CMD-004')}。负例的评分缺失不代表排除论证失败，但两条负例的排除证据条数均下降，作为本轮的反向信号单列。

## 4. 结论与限制

- 优化版把 POC 成功标准从“能运行/能看到回显”推进到“结果区域、真/假对照、独立回查、Token 新鲜度、字段长度、命令输出与反射区分”，与工作包4实测适配问题一一对应。
- 分类指标没有提升空间；不能把本轮写成“准确率提升”。如果个别样本的契约评分不变，说明基线 Prompt 已经覆盖该要求，优化条款对该样本是冗余的。
- 反向信号：两个负例的排除证据条数分别从 4→3、7→5，说明新增的 POC 条款可能挤压“排除条件”论证；下一轮应把负例排除证据的最小条数和必填字段写得更明确，而不是只增加 POC 要求。
- 格式退步：严格静态协议 5/14→4/14（`vulnerability_type` 子类型、CMD-003 `success_criteria` 类型错误）。因此本轮是“POC 契约改善 + 格式合规退步”的混合结果，不能称为全面成功；已登记 CR-008。
- 本轮仍是同一模型家族、同一执行者、公开靶场小样本，不能外推泛化效果；优化版与基线使用相同输入，故不涉及输入变体混淆。
- `poc_result` 仍为 not_run：模型 POC 未直接执行；实际执行的是人工适配参考 POC。POC 契约评分不代表模型 POC 可运行率。
"""
    (ROOT / "results" / "optimization_report.md").write_text(report, encoding="utf-8")
    print(json.dumps({
        "samples": len(table),
        "class_changed": len(changed),
        "poc_improved": len(improved),
        "poc_regressed": len(regressed),
        "baseline_poc_total": f"{base_total_score}/{base_total_max}",
        "variant_poc_total": f"{var_total_score}/{var_total_max}",
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
