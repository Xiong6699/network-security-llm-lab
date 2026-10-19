"""Integrity and redaction checks for the wp4-poc-01 evidence set."""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
VALIDATION = ROOT / "verification" / "validation_log"
EVIDENCE = ROOT / "verification" / "evidence"
OUT = ROOT / "verification" / "checks" / "evidence_integrity.json"
TZ = timezone(timedelta(hours=8))
REQUIRED = ["request.redacted.json", "response.redacted.txt", "observation.json", "restore_result.json"]
PARENTS = {
    "SQLI-001", "SQLI-002", "SQLI-003", "SQLI-005",
    "XSS-001", "XSS-002", "XSS-003", "XSS-004", "XSS-005",
    "CMD-001", "CMD-002", "CMD-003", "CMD-004", "AUTH-001",
}


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    checks = []
    samples = set()
    errors = 0
    warnings = 0
    secret_hits = 0
    for log_path in sorted(VALIDATION.glob("wp4-*.json")):
        log = json.loads(log_path.read_text(encoding="utf-8"))
        run_id = log["run_id"]
        run_dir = EVIDENCE / run_id
        samples.add(log["sample_id"])
        run_errors = []
        run_warnings = []
        missing = [name for name in REQUIRED if not (run_dir / name).exists()]
        if missing:
            run_errors.append(f"missing files: {missing}")
        request_count = 0
        if (run_dir / "request.redacted.json").exists():
            requests = json.loads((run_dir / "request.redacted.json").read_text(encoding="utf-8"))
            request_count = len(requests)
            if not requests:
                run_errors.append("empty request list")
            for index, record in enumerate(requests):
                headers = {k.lower() for k in record.get("request_headers", {})}
                if "cookie" in headers:
                    run_errors.append(f"request {index}: raw Cookie header stored")
                if not record.get("response_sha256"):
                    run_errors.append(f"request {index}: missing response hash")
        response_text = ""
        if (run_dir / "response.redacted.txt").exists():
            response_text = (run_dir / "response.redacted.txt").read_text(encoding="utf-8")
            if not response_text.strip():
                run_errors.append("empty response record")
            if re.search(r"PHPSESSID=(?!<redacted>)", response_text):
                secret_hits += 1
                run_errors.append("unredacted PHPSESSID in response record")
            if re.search(r"\bAuth=(?!<redacted>)", response_text):
                secret_hits += 1
                run_errors.append("unredacted Auth cookie in response record")
            if re.search(r"(password|passwd)=\S+", response_text, re.I) and "wp4" not in response_text.lower():
                run_warnings.append("possible unredacted password field in response record")
        observation = {}
        if (run_dir / "observation.json").exists():
            observation = json.loads((run_dir / "observation.json").read_text(encoding="utf-8"))
            if not observation.get("observations"):
                run_errors.append("empty observation object")
            for artifact in observation.get("artifacts", []):
                path = ROOT / artifact["path"]
                if not path.exists():
                    run_errors.append(f"missing artifact: {artifact['path']}")
                elif sha256(path) != artifact["sha256"]:
                    run_errors.append(f"artifact hash mismatch: {artifact['path']}")
        if log["sample_id"].startswith("XSS"):
            browser = run_dir / "browser.json"
            if not browser.exists():
                run_errors.append("XSS run without browser.json")
            else:
                data = json.loads(browser.read_text(encoding="utf-8"))
                if "executed" not in data:
                    run_errors.append("browser.json without executed flag")
                screenshot = data.get("screenshot")
                if screenshot and not (ROOT / screenshot).exists():
                    run_errors.append("browser screenshot missing")
        if not observation.get("success_criteria"):
            run_warnings.append("no success criteria recorded")
        if not observation.get("limitations"):
            run_warnings.append("no limitations recorded")
        if not log.get("ground_truth"):
            run_errors.append("no ground truth")
        if log.get("review_status") != "single_person_review_only":
            run_warnings.append("review status is not the expected single-person marker")
        errors += len(run_errors)
        warnings += len(run_warnings)
        checks.append({
            "run_id": run_id,
            "sample_id": log["sample_id"],
            "request_count": request_count,
            "required_files_present": not missing,
            "errors": run_errors,
            "warnings": run_warnings,
            "status": "pass" if not run_errors else "fail",
        })
    missing_parents = sorted(PARENTS - samples)
    summary = {
        "checked_at": datetime.now(TZ).isoformat(timespec="seconds"),
        "timezone": "+08:00",
        "runs_checked": len(checks),
        "runs_passed": sum(1 for check in checks if check["status"] == "pass"),
        "runs_failed": sum(1 for check in checks if check["status"] == "fail"),
        "error_count": errors,
        "warning_count": warnings,
        "unredacted_secret_hits": secret_hits,
        "parents_covered": sorted(samples),
        "missing_parents": missing_parents,
        "checks": checks,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "runs_checked": summary["runs_checked"],
        "runs_passed": summary["runs_passed"],
        "runs_failed": summary["runs_failed"],
        "missing_parents": missing_parents,
        "unredacted_secret_hits": secret_hits,
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
