"""Generate the case plan/execution status table."""
from __future__ import annotations

import csv
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOGS = ROOT / "verification" / "validation_log"
OUT = ROOT / "verification" / "cases" / "case_plan.csv"

PLANNED = [
    ("SQLI-001", "Less-1/index.php?id", "env=sqli-labs-wsl-01|role=anonymous", "run_sqli.py", "触发", "SQL注入"),
    ("SQLI-002", "Less-11/index.php:uname", "env=sqli-labs-wsl-01|role=anonymous", "run_sqli.py", "触发", "SQL注入"),
    ("SQLI-003", "Less-25/index.php?id", "env=sqli-labs-wsl-01|role=anonymous", "run_sqli.py", "触发", "SQL注入"),
    ("SQLI-005", "Less-24 register/login/pass_change", "env=sqli-labs-wsl-01|role=anonymous", "run_sqli005.py", "触发", "SQL注入"),
    ("XSS-001", "xss_r name", "env=dvwa-wsl-01|security=low", "run_xss.py", "触发", "XSS"),
    ("XSS-002", "xss_r name", "env=dvwa-wsl-01|security=medium", "run_xss.py", "触发", "XSS"),
    ("XSS-003", "xss_r name", "env=dvwa-wsl-01|security=high", "run_xss.py", "触发", "XSS"),
    ("XSS-004", "xss_r name+token", "env=dvwa-wsl-01|security=impossible", "run_xss.py", "未触发", "XSS"),
    ("XSS-005", "xss_s write/read", "env=dvwa-wsl-01|security=low", "run_xss.py", "触发", "XSS"),
    ("CMD-001", "exec ip", "env=dvwa-wsl-01|security=low", "run_cmd.py", "触发", "命令注入"),
    ("CMD-002", "exec ip", "env=dvwa-wsl-01|security=medium", "run_cmd.py", "触发", "命令注入"),
    ("CMD-003", "exec ip", "env=dvwa-wsl-01|security=high", "run_cmd.py", "触发", "命令注入"),
    ("CMD-004", "exec ip+token", "env=dvwa-wsl-01|security=impossible", "run_cmd.py", "未触发", "命令注入"),
    ("AUTH-001", "authbypass page/read/update", "env=dvwa-wsl-01|security=low", "run_auth.py", "触发", "权限越权"),
    ("AUTH-001", "authbypass page/read/update", "env=dvwa-wsl-01|security=medium", "run_auth.py", "触发", "权限越权"),
    ("AUTH-001", "authbypass page/read/update", "env=dvwa-wsl-01|security=high", "run_auth.py", "触发", "权限越权"),
    ("AUTH-001", "authbypass page/read/update", "env=dvwa-wsl-01|security=impossible", "run_auth.py", "未触发", "权限越权"),
]


def main() -> None:
    logs = [json.loads(p.read_text(encoding="utf-8")) for p in sorted(LOGS.glob("wp4-*.json"))]
    by_key = {}
    for log in logs:
        level = ""
        for part in log["condition_key"].split("|"):
            if part.startswith("security="):
                level = part.split("=", 1)[1]
        by_key[(log["sample_id"], level)] = log
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "sample_id", "vulnerability_type", "path_id", "planned_condition",
            "poc_script", "expected_trigger", "actual_trigger", "status",
            "run_id", "evidence_dir",
        ])
        for sample, path, condition, script, expected, vtype in PLANNED:
            level = ""
            for part in condition.split("|"):
                if part.startswith("security="):
                    level = part.split("=", 1)[1]
            log = by_key.get((sample, level if sample == "AUTH-001" else ""))
            if log is None:
                # Non-AUTH conditions include the level in the condition key; match by sample + level anywhere.
                log = next((l for l in logs if l["sample_id"] == sample and level and level in l["condition_key"]), None)
            if log is None and sample != "AUTH-001":
                log = next((l for l in logs if l["sample_id"] == sample), None)
            status = "completed" if log else "not_run"
            writer.writerow([
                sample, vtype, path, condition, script, expected,
                log["trigger_result"] if log else "",
                status,
                log["run_id"] if log else "",
                f"verification/evidence/{log['run_id']}" if log else "",
            ])
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
