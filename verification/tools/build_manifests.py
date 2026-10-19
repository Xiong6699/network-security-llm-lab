"""Generate source checksums and the experiment manifest for wp4-poc-01."""
from __future__ import annotations

import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFESTS = ROOT / "verification" / "manifests"
VALIDATION = ROOT / "verification" / "validation_log"
TZ = timezone(timedelta(hours=8))

DEPLOYMENTS = {
    "sqli-labs-wsl-01": {
        "source_dir": Path("/srv/source_projects/sqli-labs"),
        "deployed_dir": Path("/srv/web/sqli-labs"),
        "files": [
            "Less-1/index.php",
            "Less-11/index.php",
            "Less-25/index.php",
            "Less-24/login.php",
            "Less-24/login_create.php",
            "Less-24/pass_change.php",
            "Less-24/logged-in.php",
            "sql-connections/sql-connect.php",
            "sql-connections/db-creds.inc",
            "sql-connections/setup-db.php",
        ],
    },
    "dvwa-wsl-01": {
        "source_dir": Path("/srv/source_projects/DVWA"),
        "deployed_dir": Path("/srv/web/dvwa"),
        "files": [
            "vulnerabilities/xss_r/source/low.php",
            "vulnerabilities/xss_r/source/medium.php",
            "vulnerabilities/xss_r/source/high.php",
            "vulnerabilities/xss_r/source/impossible.php",
            "vulnerabilities/xss_s/source/low.php",
            "vulnerabilities/xss_s/index.php",
            "vulnerabilities/exec/source/low.php",
            "vulnerabilities/exec/source/medium.php",
            "vulnerabilities/exec/source/high.php",
            "vulnerabilities/exec/source/impossible.php",
            "vulnerabilities/exec/index.php",
            "vulnerabilities/authbypass/index.php",
            "vulnerabilities/authbypass/source/low.php",
            "vulnerabilities/authbypass/source/medium.php",
            "vulnerabilities/authbypass/source/high.php",
            "vulnerabilities/authbypass/source/impossible.php",
            "vulnerabilities/authbypass/get_user_data.php",
            "vulnerabilities/authbypass/change_user_details.php",
            "vulnerabilities/authbypass/authbypass.js",
            "dvwa/includes/dvwaPage.inc.php",
            "login.php",
            "setup.php",
            "security.php",
        ],
    },
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def git_commit(path: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(path), "rev-parse", "HEAD"],
        capture_output=True, text=True, check=True).stdout.strip()


def build_checksums() -> dict:
    result = {
        "generated_at": datetime.now(TZ).isoformat(timespec="seconds"),
        "timezone": "+08:00",
        "deployments": {},
        "local_config_differences": [
            "DVWA: config/config.inc.php added locally from config.inc.php.dist; DB credentials are local-only and not committed.",
            "DVWA: default_security_level set to low for the local lab; individual requests force the target level through the security cookie.",
            "SQLi-Labs: sql-connections/db-creds.inc is unchanged (root over the local unix socket); PHP 5.6 is configured with mysql.default_socket=/run/mysqld/mysqld.sock.",
            "Both labs run on PHP's built-in HTTP server rather than Apache; this changes the SAPI, not the audited PHP source.",
        ],
    }
    for deployment_id, spec in DEPLOYMENTS.items():
        entry = {
            "source_dir": str(spec["source_dir"]),
            "deployed_dir": str(spec["deployed_dir"]),
            "commit": git_commit(spec["source_dir"]),
            "files": {},
        }
        for rel in spec["files"]:
            src = spec["source_dir"] / rel
            dep = spec["deployed_dir"] / rel
            entry["files"][rel] = {
                "source_sha256": sha256(src),
                "deployed_sha256": sha256(dep),
                "identical": sha256(src) == sha256(dep),
                "bytes": src.stat().st_size,
            }
        result["deployments"][deployment_id] = entry
    return result


def build_manifest() -> dict:
    runs = []
    for log_path in sorted(VALIDATION.glob("wp4-*.json")):
        log = json.loads(log_path.read_text(encoding="utf-8"))
        runs.append({
            "run_id": log["run_id"],
            "sample_id": log["sample_id"],
            "path_id": log["path_id"],
            "condition_key": log["condition_key"],
            "trigger_result": log["trigger_result"],
            "ground_truth": log["ground_truth"],
            "validation_log": f"verification/validation_log/{log_path.name}",
            "evidence_dir": f"verification/evidence/{log['run_id']}",
        })
    return {
        "batch_id": "wp4-poc-01",
        "created_at": datetime.now(TZ).isoformat(timespec="seconds"),
        "timezone": "+08:00",
        "executor": "wp4-agent (single-person review)",
        "environment": {
            "host": "Windows 11 26200 + WSL2 Ubuntu 22.04.5",
            "dvwa": "http://127.0.0.1:9080 (PHP 8.1.2, MariaDB 10.6.23)",
            "sqli_labs": "http://127.0.0.1:9081 (PHP 5.6.40 ext/mysql, MariaDB 10.6.23)",
            "browser": "Google Chrome 155.0.8059.82 headless via playwright-core 1.64.1",
        },
        "samples": 14,
        "runs": runs,
        "prompt_versions": ["v1", "v2", "final", "final-wp4-v1"],
        "input_version": "v2",
        "model_batches": [
            {
                "batch_id": "wp4-baseline-final",
                "prompt_version": "final",
                "model": "DeepSeek Harness subagent (deepseek-flash)",
                "samples": 14,
                "interface": "subagent independent context; not a formal model API record",
                "raw_outputs": "results/batches/wp4-baseline-final/raw_outputs/",
                "comparison": "results/batches/wp4-baseline-final/comparison.csv",
                "metrics": "results/batches/wp4-baseline-final/metrics.csv",
                "limitations": [
                    "model snapshot, sampling parameters and token usage unknown",
                    "multi-packet prompts were provided together rather than incrementally appended",
                    "same model family as the verification assistant; not a fully independent blind review",
                ],
            },
            {
                "batch_id": "wp4-final-wp4-v1",
                "prompt_version": "final-wp4-v1",
                "base_version": "final",
                "model": "DeepSeek Harness subagent (deepseek-flash)",
                "samples": 14,
                "interface": "subagent independent context; not a formal model API record",
                "raw_outputs": "results/batches/wp4-final-wp4-v1/raw_outputs/",
                "comparison": "results/batches/wp4-final-wp4-v1/comparison.csv",
                "version_comparison": "results/batches/wp4-final-wp4-v1/version_comparison.csv",
                "metrics": "results/batches/wp4-final-wp4-v1/metrics.csv",
                "change_requests": "results/change_requests.csv",
                "optimization_report": "results/optimization_report.md",
                "limitations": [
                    "same model family and executor as baseline",
                    "POC contract score is a keyword/completeness heuristic, not a manual quality score",
                    "model POCs were not executed; poc_result remains not_run",
                ],
            },
        ],
        "notes": [
            "This manifest covers the POC/ground-truth batch only.",
            "No formal model output is counted in this batch; see results/batches/ for model batches.",
            "All test objects were dedicated to this lab and removed or restored.",
        ],
    }


def main() -> None:
    MANIFESTS.mkdir(parents=True, exist_ok=True)
    checksums = build_checksums()
    (MANIFESTS / "source_checksums.json").write_text(
        json.dumps(checksums, ensure_ascii=False, indent=2), encoding="utf-8")
    manifest = build_manifest()
    (MANIFESTS / "experiment_manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    mismatches = [
        f"{dep}/{name}" for dep, entry in checksums["deployments"].items()
        for name, info in entry["files"].items() if not info["identical"]]
    print(json.dumps({
        "deployments": list(checksums["deployments"]),
        "runs": len(manifest["runs"]),
        "mismatches": mismatches,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
