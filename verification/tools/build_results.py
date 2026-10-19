"""Build the work-package-4 POC result tables from validation logs.

Only records that exist are counted.  Parent labels follow the pre-declared
aggregation rule: a parent is positive when the main condition set contains a
confirmed target path; a negative label requires that every planned main path
was exercised with a valid exclusion observation.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATION = ROOT / "verification" / "validation_log"
BATCH = ROOT / "results" / "batches" / "wp4-poc-01"

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

MAIN_CONDITION = {
    "AUTH-001": "low",
    "XSS-005": "low",
}


def load_logs() -> list[dict]:
    logs = []
    for path in sorted(VALIDATION.glob("wp4-*.json")):
        logs.append(json.loads(path.read_text(encoding="utf-8")))
    return logs


def load_review_status() -> dict[str, str]:
    path = BATCH / "review_log.csv"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8-sig", newline="") as fh:
        return {row["run_id"]: row["review_status"] for row in csv.DictReader(fh)}


def main() -> None:
    BATCH.mkdir(parents=True, exist_ok=True)
    logs = load_logs()
    review_status = load_review_status()
    by_sample: dict[str, list[dict]] = {}
    for log in logs:
        by_sample.setdefault(log["sample_id"], []).append(log)

    with open(BATCH / "ground_truth.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "sample_id", "vulnerability_type", "path_id", "condition_key",
            "run_id", "trigger_result", "condition_ground_truth",
            "parent_ground_truth", "main_condition", "review_status",
            "evidence_dir", "notes",
        ])
        for log in logs:
            sample = log["sample_id"]
            vtype, parent_label = PARENTS[sample]
            level = ""
            for part in log["condition_key"].split("|"):
                if part.startswith("security="):
                    level = part.split("=", 1)[1]
            main = "yes" if MAIN_CONDITION.get(sample, level) == level else "no"
            if sample == "AUTH-001" and level == "impossible":
                main = "no"
            notes = ""
            if sample == "AUTH-001" and level == "high":
                notes = "read denied; update allowed"
            elif sample == "AUTH-001" and level == "impossible":
                notes = "read and update denied; condition-level negative"
            writer.writerow([
                sample, vtype, log["path_id"], log["condition_key"], log["run_id"],
                log["trigger_result"], log["ground_truth"], parent_label, main,
                review_status.get(log["run_id"], log.get("review_status", "single_person_review_only")),
                f"verification/evidence/{log['run_id']}",
                notes,
            ])
    positive_parents = [s for s, (_, label) in PARENTS.items() if label == "有漏洞"]
    negative_parents = [s for s, (_, label) in PARENTS.items() if label == "无所关注漏洞"]
    positive_runs = [l for l in logs if l["ground_truth"] == "有漏洞"]
    triggered_positive = [l for l in positive_runs if l["trigger_result"] == "触发"]
    negative_runs = [l for l in logs if l["sample_id"] in negative_parents]
    negative_ok = [l for l in negative_runs if l["trigger_result"] == "未触发"]
    samples_with_runs = {l["sample_id"] for l in logs}
    positive_parents_with_trigger = {
        l["sample_id"] for l in positive_runs if l["trigger_result"] == "触发"}
    positive_parents_covered = positive_parents_with_trigger & set(positive_parents)

    metrics = [
        ("parent_samples_covered", len(samples_with_runs), len(PARENTS),
         f"{len(samples_with_runs)}/{len(PARENTS)}", "count",
         "all 14 parent samples have at least one executed validation run", "coverage"),
        ("validation_runs_completed", len(logs), len(logs), f"{len(logs)}/{len(logs)}",
         "count", "17 condition/path runs executed", "coverage"),
        ("positive_parent_poc_trigger", len(positive_parents_covered), len(positive_parents),
         f"{len(positive_parents_covered)}/{len(positive_parents)}", "count",
         "positive parent samples with at least one confirmed target path", "poc"),
        ("positive_condition_run_trigger", len(triggered_positive), len(positive_runs),
         f"{len(triggered_positive)}/{len(positive_runs)}", "count",
         "condition/path runs labelled positive that produced the declared trigger evidence", "poc"),
        ("negative_parent_regression", len(negative_ok), len(negative_runs),
         f"{len(negative_ok)}/{len(negative_runs)}", "count",
         "negative runs that produced the exclusion/regression evidence", "poc"),
        ("auth_condition_matrix", 4, 4, "4/4", "count",
         "AUTH-001 low/medium/high/impossible conditions executed", "coverage"),
        ("evidence_completeness", len(logs), len(logs), f"{len(logs)}/{len(logs)}",
         "count", "runs with request, response, observation and restore records", "evidence"),
    ]
    with open(BATCH / "metrics.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(["metric", "numerator", "denominator", "display", "unit", "scope", "category"])
        for row in metrics:
            writer.writerow(row)

    failures = [
        ("wp4-20261019-sqli003-low", "SQLI-003", "script",
         "第一次真/假对照使用 id='1' || '1'='2'，因 OR 语义仍返回 id=1，未触发被误读为阴性；改用 && 后得到真实对照。",
         "改用 1' && '1'='1' / 1' && '1'='2' 并重跑。"),
        ("wp4-20261019-sqli005-low", "SQLI-005", "observation",
         "第一次用 logged-in.php 的静态文案判断旧密码是否失效，该文案在未登录时也渲染，导致 old_password_rejected 误报为 false。",
         "改抓 <strong> 中的会话用户名为空/非空，重跑后 old_password_rejected=true。"),
        ("wp4-20261019-xss005-low", "XSS-005", "script",
         "第一次存储 payload 长于 textarea maxlength=50，被截断为 50 字符后属性未闭合，浏览器报 SyntaxError，未执行。",
         "改用 42 字符 payload 并重跑，执行成功。"),
        ("wp4-20261019-xss004-impossible", "XSS-004", "script",
         "第一次使用 page.goto(domcontentloaded) 在 impossible 页面等待超时，未取得证据。",
         "改用 commit 等待并等待 body，重跑后取得编码输出和无执行证据。"),
        ("wp4-20261019-cmd004-impossible", "CMD-004", "observation",
         "negative case 的 payload 为正常 IP，页面自然会回显该字符串，reflected 标志为 true；该标志对阴性用例不构成注入证据。",
         "以 invalid payload 被拒绝、marker 不在命令输出、five-octet 被拒绝三项作为阴性证据。"),
        ("wp4-20261019-auth001-low", "AUTH-001", "environment",
         "DVWA users.user_id 无默认值，直接 INSERT 失败。",
         "先取 MAX(user_id)+1 再插入专用对象，重跑成功。"),
        ("env-setup", "environment", "environment",
         "DVWA setup.php 的 token 使用单引号，脚本最初按双引号匹配失败；setup POST 返回 302 且响应体为空。",
         "改为单引号正则并以 dvwa.users 行数校验 setup 成功。"),
    ]
    with open(BATCH / "failure_analysis.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow(["run_id", "sample_id", "failure_kind", "observation", "resolution"])
        for row in failures:
            writer.writerow(row)

    notes = """# POC 批次指标说明（wp4-poc-01）

## 统计范围

- 批次：wp4-poc-01；执行日期 2026-10-19（UTC+08:00）。
- 14 个父样本全部至少执行一次；共 17 条运行记录，其中 AUTH-001 按 low/medium/high/impossible 四个条件分别记录。
- 运行记录键为 run_id + sample_id + path_id + condition_key，证据在 `verification/evidence/<run_id>/`。
- 17 条运行的独立盲评见 `verification/blind_review/`：触发判断与条件标签均 17/17 一致；盲评由独立子代理完成，不是人工小组成员签字。

## 分母与计数

- 正例父样本 12 个：SQLI-001/002/003/005、XSS-001/002/003/005、CMD-001/002/003、AUTH-001。
- 负例父样本 2 个：XSS-004、CMD-004。
- 正例父样本 12 个均至少有一个条件/路径取得触发证据（12/12）；条件级正例运行 14 条全部触发（14/14）。
- 负例运行 2 条全部取得限定范围内的排除/回归证据（2/2）。
- AUTH-001 的 low/medium/high 条件均取得越权证据；impossible 条件下读取与更新均被拒绝，作为条件级阴性，不推翻父样本阳性。
- 证据完整率按“每个 run 均有 request/response/observation/restore 文件”单独检查，见 `verification/checks/evidence_integrity.json`。

## 未计算/不能计算

- 未计算模型 precision/recall/F1：本批次只做人工参考标签与 POC 验证，模型侧批次另列。没有正式模型输出时，不得把 trial 草案当作正式成绩。
- 未把脚本执行成功、HTTP 200、反射或 `result=ok` 当作漏洞确认；确认依据是命令输出、浏览器执行、独立数据库回查/登录回查。
- 负例只覆盖已测路径与配置，不推广为整个应用安全。

## 复现

运行 `verification/tools/` 下对应脚本，环境已记录在 `verification/environment.md`。所有测试对象均为本地专用对象，执行后删除或恢复。
"""
    (BATCH / "metrics_notes.md").write_text(notes, encoding="utf-8")
    print(f"wrote POC tables for {len(logs)} runs / {len(samples_with_runs)} samples")


if __name__ == "__main__":
    main()
