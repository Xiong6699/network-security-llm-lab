"""Build the fixed teaching sample set from pinned local Git objects.

Run from any directory with Python 3. No third-party dependencies required.
This is a curated extractor for the listed files, not a generic PHP parser.
"""
from pathlib import Path
import csv
import hashlib
import json
import subprocess

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT.parents[1] / "source_projects"
PINS = {
    "sqli-labs": "e96f21776372c8613a7e565106e62bc01a59355e",
    "DVWA": "068d974487a297c155c48722f9fcf7180a83adc4",
}
URLS = {"sqli-labs": "https://github.com/Audi-1/sqli-labs", "DVWA": "https://github.com/digininja/DVWA"}
SPEC = [
    ("SQLI-001", "sqli-labs", "Less-1/index.php", "SQL注入", "脆弱候选", False),
    ("SQLI-002", "sqli-labs", "Less-11/index.php", "SQL注入", "脆弱候选", False),
    ("SQLI-003", "sqli-labs", "Less-25/index.php", "SQL注入", "复杂过滤候选", False),
]
for prefix, module, kind in [("XSS", "xss_r", "XSS"), ("CMD", "exec", "命令注入")]:
    for i, level in enumerate(["low", "medium", "high", "impossible"], 1):
        group = "待审计"
        SPEC.append((f"{prefix}-{i:03}", "DVWA", f"vulnerabilities/{module}/source/{level}.php", kind, group, False))


def source(project, path):
    return subprocess.check_output(["git", "-C", str(SOURCES / project), "show", f"{PINS[project]}:{path}"])


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def table(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)


def merge_manual_rows(path, rows, key="sample_id"):
    """Initialize new records without overwriting human labels or evidence."""
    old = {}
    if path.exists():
        with path.open(encoding="utf-8-sig", newline="") as f:
            old = {r[key]: r for r in csv.DictReader(f)}
    merged = [old.get(r[key], r) for r in rows]
    merged.extend(r for sid, r in old.items() if sid not in {x[key] for x in rows})
    table(path, merged)


def clean(raw):
    # Only strip empty lines and inactive //echo or //print_r in these files.
    # Do not rewrite strings, inline comments, indentation, or security checks.
    selected = []
    inside = False
    for n, line in enumerate(raw.decode("utf-8").splitlines(), 1):
        if line.strip() == "<?php":
            inside = True
            continue
        if line.strip() == "?>":
            inside = False
            continue
        if not inside or not line.strip():
            continue
        # Keep source/security comments. Exclude only inactive //echo or //print_r.
        if line.lstrip().startswith(("//echo", "//print_r")):
            continue
        operation = "retained"
        selected.append((line, n, operation))
    if not selected:
        raise ValueError("No selected PHP body")
    lines = ["<?php"] + [x[0] for x in selected] + ["?>"]
    mapping = [{"normalized_line": 1, "original_line": "", "operation": "wrapper"}]
    mapping += [{"normalized_line": i + 2, "original_line": x[1], "operation": x[2]} for i, x in enumerate(selected)]
    mapping += [{"normalized_line": len(lines), "original_line": "", "operation": "wrapper"}]
    return "\n".join(lines) + "\n", mapping


def main():
    rows, labels = [], []
    for sid, project, path, kind, group, derived in SPEC:
        raw = source(project, path)
        rawpath = ROOT / "raw_samples" / f"{sid}.php"
        rawpath.parent.mkdir(parents=True, exist_ok=True)
        rawpath.write_bytes(raw)
        code, mapping = clean(raw)
        write(ROOT / "normalized_samples" / f"{sid}.php", code)
        table(ROOT / "line_maps" / f"{sid}.csv", mapping)
        is_sql = kind == "SQL注入"
        params = "POST: uname、passwd" if sid == "SQLI-002" else "GET: id" if is_sql else "GET: name" if kind == "XSS" else "POST: Submit、ip（代码实际使用 $_REQUEST 读取 ip）"
        if sid in ("XSS-004", "CMD-004"):
            params += "；user_token（与当前会话 session_token 对应）"
        dependency = "sql-connections/sql-connect.php；db-creds.inc；security 数据库及 users 表" if is_sql else "外围处理器、dvwaPage.inc.php；登录会话、页面渲染与难度选择；涉及 token 时还需会话 token"
        context = "包含连接文件后，在顶层请求处理中读取参数、构造并执行查询，直接输出结果或错误。连接实现另存 context/sqli-connect.php。" if is_sql else "外围处理器启动登录会话，按配置包含本片段，再把 $html 插入 page['body']，最后调用 dvwaHtmlEcho 输出。相应外围源码另存 context/。"
        limitation = "审计片段不能独立部署；mysql_* 接口需要兼容运行环境；不得把 PHP 接口错误当作误报。" if is_sql else "审计片段不能独立部署；PHP 版本、浏览器行为、认证开关与 token 状态尚未实测。"
        if kind == "命令注入":
            limitation += " 命令行为受操作系统、shell、ping 可用性和 shell_exec 配置影响；Windows 与 Linux 分支均须保留。"
        mapped = [m["original_line"] for m in mapping if m["original_line"]]
        license_note = "GPL-3.0-or-later；见 provenance/DVWA-COPYING.txt 与上游 README" if project == "DVWA" else "课程指导指定教学来源；本次固定提交未发现独立 LICENSE/COPYING 文件；进一步传播许可待核实"
        metadata = {
            "sample_id": sid, "project": project, "source_url": URLS[project], "commit": PINS[project],
            "source_file": path, "source_line_start": min(mapped), "source_line_end": max(mapped),
            "license_or_authorization": license_note, "language": "PHP", "audit_scope": kind,
            "entry": "顶层请求处理片段", "parameters": params, "dependencies": dependency,
            "context": context, "limitations": limitation,
            "transformation": "无语义变更设计",
            "raw_sha256": hashlib.sha256(raw).hexdigest(), "normalized_sha256": hashlib.sha256(code.encode()).hexdigest(),
            "normalized_lines": len(code.splitlines()), "cross_fragment_dependency": True,
            "preprocess_version": "v1", "runtime_validation": "pending",
        }
        meta_path = ROOT / "sample_metadata" / f"{sid}.json"
        if meta_path.exists():
            previous_meta = json.loads(meta_path.read_text(encoding="utf-8"))
            for field in ("runtime_validation", "runtime_evidence", "validated_environment"):
                if field in previous_meta:
                    metadata[field] = previous_meta[field]
        metadata["preprocess_version"] = "v2"
        write(meta_path, json.dumps(metadata, ensure_ascii=False, indent=2) + "\n")
        # Do not send upstream level names, source filenames or candidate labels to the model.
        prompt_input = f"""样本 ID：{sid}
来源引用：内部台账同 ID（本审计输入隐藏原始关卡名称；完整追溯信息由评估人员保管）
语言：PHP
审计关注类型：{kind}
入口：顶层请求处理逻辑
请求参数：{params}
调用及输出关系：{context}
外部依赖：{dependency}
已知限制：{limitation}
行号约定：报告 normalized_samples/{sid}.php 的 1 起始行号；人工使用 line_maps/{sid}.csv 回溯。

代码片段：
```php
{code.rstrip()}
```

期望输出：判断存在相关漏洞、不存在所关注漏洞，或证据不足；给出输入来源、关键处理、危险操作、代码行号、成立条件和需要补充的证据。不能把危险函数名称本身当作漏洞成立证据。此文件是代码输入模板实例，不代替提示词组的完整审计 Prompt。
"""
        write(ROOT / "llm_inputs" / f"{sid}.md", prompt_input)
        rows.append({"sample_id": sid, "project": project, "commit": PINS[project], "source_file": path, "source_url": URLS[project], "authorization": license_note, "language": "PHP", "audit_scope": kind, "parameters": params, "source_start": min(mapped), "source_end": max(mapped), "normalized_lines": len(code.splitlines()), "normalized_file": f"normalized_samples/{sid}.php", "metadata_file": f"sample_metadata/{sid}.json", "line_map": f"line_maps/{sid}.csv", "review_status": "见review_log.csv；构建本身不执行复核", "runtime_status": "未验证"})
        labels.append({"sample_id": sid, "ground_truth": "待验证", "evidence": "尚无POC结果", "runtime_status": "未验证"})
    table(ROOT / "samples.csv", rows)
    merge_manual_rows(ROOT / "evaluation_private" / "labels.csv", labels)
    for project, path, out in [
        ("sqli-labs", "sql-connections/sql-connect.php", "context/sqli-connect.php"),
        ("DVWA", "vulnerabilities/xss_r/index.php", "context/xss-handler.php"),
        ("DVWA", "vulnerabilities/exec/index.php", "context/cmd-handler.php"),
        ("DVWA", "dvwa/includes/dvwaPage.inc.php", "context/dvwaPage.inc.php"),
        ("DVWA", "COPYING.txt", "provenance/DVWA-COPYING.txt"),
        ("DVWA", "README.md", "provenance/DVWA-README.md"),
        ("sqli-labs", "readme.md", "provenance/SQLi-Labs-readme.md"),
    ]:
        data = source(project, path)
        (ROOT / out).parent.mkdir(parents=True, exist_ok=True)
        (ROOT / out).write_bytes(data)
    write(ROOT / "provenance" / "source_versions.json", json.dumps({"pins": PINS, "urls": URLS, "source_access_date": "2026-10-12", "extraction": "git show COMMIT:PATH; raw files preserve exact object bytes", "windows_limitation": "SQLi-Labs contains case-colliding filenames in Less-24 and Less-40. SQLI-005 uses exact Less-24 paths read from Git objects; use Linux for faithful full deployment.", "preprocess_version": "v2"}, ensure_ascii=False, indent=2) + "\n")
    # Build linked multi-file scenarios and append their parent records to the ledger.
    from build_complex_samples import build_complex_samples
    complex_rows = build_complex_samples()
    table(ROOT / "samples.csv", rows + complex_rows)
    print(f"Built {len(rows)} baseline samples and {len(complex_rows)} workflow samples. Human evaluation records preserved.")


if __name__ == "__main__":
    main()
