"""Repeatable, read-only checks for the work package 2 artifacts."""
import argparse
import copy
import csv
import hashlib
import json
from pathlib import Path
import re
import runpy
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PROMPTS = ROOT / "prompts"
prepare = runpy.run_path(str(PROMPTS / "tools/prepare_inputs.py"))
validator = runpy.run_path(str(PROMPTS / "tools/check_outputs.py"))


def ensure(ok, message):
    if not ok:
        raise ValueError(message)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="Optional JSON report path")
    args = parser.parse_args()

    expected_files, expected_manifest = prepare["build"]()
    manifest_path = PROMPTS / "prepared" / "manifest.json"
    for path, expected in expected_files.items():
        if path == manifest_path:
            continue
        ensure(path.is_file() and path.read_bytes() == expected, f"Prepared file differs: {path}")
    actual_manifest = json.loads((PROMPTS / "prepared/manifest.json").read_text(encoding="utf-8"))
    if not (ROOT / ".git").exists():
        # Without a Git checkout the generator cannot recover the source commit;
        # keep the recorded value and compare every other manifest field.
        expected_manifest["source_commit_for_workpackage1"] = actual_manifest.get("source_commit_for_workpackage1")
    ensure(actual_manifest == expected_manifest, "Prepared manifest differs")
    ensure(len(actual_manifest["entries"]) == 51 and actual_manifest["parent_sample_count"] == 14, "Prepared count differs")
    for entry in actual_manifest["entries"]:
        prepared = ROOT / entry["prompt_file"]
        source = ROOT / entry["source_input"]
        body = prepared.read_text(encoding="utf-8")
        source_text = source.read_text(encoding="utf-8-sig").rstrip()
        ensure(sha(prepared) == entry["prompt_sha256"] and sha(source) == entry["source_sha256"], f"Input hash differs: {prepared}")
        ensure(len(re.findall(r"^## ", body, re.M)) == 4, f"Expected four prompt sections: {prepared}")
        ensure(not re.search(r"\{\{[A-Z_]+\}\}", body), f"Unfilled placeholder: {prepared}")
        boundary = f"AUDIT_DATA_{entry['source_sha256'][:20]}"
        ensure(f"BEGIN_{boundary}\n{source_text}\nEND_{boundary}" in body, f"Input changed inside prompt: {prepared}")

    with (PROMPTS / "evaluation_records.csv").open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    ensure(len(rows) == 42, "Expected 42 formal parent/version rows")
    for row in rows:
        hashes = [e["prompt_sha256"] for e in actual_manifest["entries"] if e["sample_id"] == row["sample_id"] and e["prompt_version"] == row["prompt_version"]]
        bundle = hashlib.sha256(json.dumps(hashes).encode()).hexdigest()
        ensure(bool(hashes) and row["prompt_bundle_sha256"] == bundle, f"Formal prompt bundle differs: {row['sample_id']}")

    trial = json.loads((PROMPTS / "trial/run_manifest.json").read_text(encoding="utf-8"))
    ensure(trial["independent_model_call_count"] == 0 and trial["draft_count"] == 15, "Trial scope differs")
    ensure(sha(PROMPTS / "prepared/manifest.json") == trial["preparation_manifest_sha256"], "Trial preparation hash differs")
    for artifact in trial["poc_artifacts"]:
        ensure(sha(ROOT / artifact["path"]) == artifact["sha256"] and artifact["execution"] == "not_run", f"POC artifact differs: {artifact['path']}")
    trial_files = sorted((PROMPTS / "trial/outputs").rglob("*.json"))
    ensure(len(trial_files) == 15 and len(trial["records"]) == 15, "Trial draft count differs")
    for record in trial["records"]:
        draft = ROOT / record["assistant_draft_path"]
        ensure(sha(draft) == record["assistant_draft_sha256"], f"Trial draft hash differs: {draft}")
        ensure(len(record["prepared_prompt_files"]) == len(record["prepared_prompt_sha256"]) and bool(record["prepared_prompt_files"]), f"Trial prompt list differs: {draft}")
        ensure(all(sha(ROOT / p) == h for p, h in zip(record["prepared_prompt_files"], record["prepared_prompt_sha256"])), f"Trial prompt hash differs: {draft}")
        ensure(validator["check"](json.loads(draft.read_text(encoding="utf-8")))["status"] == "passed_static_protocol", f"Trial draft invalid: {draft}")

    example = json.loads((PROMPTS / "trial/outputs/final/SQLI-001.json").read_text(encoding="utf-8"))
    mutations = {
        "line_range": lambda d: d["findings"][0]["locations"][0].update(line_start=9999),
        "quote": lambda d: d["findings"][0]["locations"][0].update(quote="a fabricated code quote"),
        "confirmation_without_runtime": lambda d: d.update(verdict="确认"),
        "missing_packet": lambda d: d.update(sample_id="AUTH-001", received_packet_ids=["AUTH-001-P1"]),
        "prediction_conflict": lambda d: d.update(prediction="未检出候选"),
        "external_artifact": lambda d: d["findings"][0]["poc"].update(artifact_path="../outside.py"),
    }
    for name, mutate in mutations.items():
        altered = copy.deepcopy(example)
        mutate(altered)
        try:
            validator["check"](altered)
        except (ValueError, KeyError, TypeError):
            pass
        else:
            raise ValueError(f"Invalid output escaped protocol check: {name}")

    for path in [PROMPTS / "tools/prepare_inputs.py", PROMPTS / "tools/check_outputs.py", Path(__file__), *(ROOT / a["path"] for a in trial["poc_artifacts"])]:
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    for artifact in trial["poc_artifacts"]:
        safe_url = runpy.run_path(str(ROOT / artifact["path"]))["local_url"]
        ensure(safe_url("http://127.0.0.1:8080", "lesson.php").startswith("http://127.0.0.1:8080/"), "Local URL rejected")
        for unsafe in ("http://example.org/", "http://user@127.0.0.1:8080/"):
            try:
                safe_url("http://127.0.0.1:8080", unsafe)
            except ValueError:
                pass
            else:
                raise ValueError(f"Unsafe URL accepted by {artifact['path']}")

    if (ROOT / ".git").exists():
        git = subprocess.run(["git", "diff", "--quiet", "HEAD", "--", "workpackage1"], cwd=ROOT, check=False)
        ensure(git.returncode == 0, "Work package 1 tracked files changed")
        workpackage1_diff = "clean"
    else:
        workpackage1_diff = "not_a_git_checkout"
    report = {
        "status": "passed_static_checks",
        "prepared_prompts": 51,
        "parent_samples": 14,
        "formal_records": 42,
        "formal_status_counts": {s: sum(r["status"] == s for r in rows) for s in sorted({r["status"] for r in rows})},
        "same_conversation_drafts_checked": 15,
        "invalid_output_cases_rejected": len(mutations),
        "poc_drafts_compiled_and_local_url_guard_checked": len(trial["poc_artifacts"]),
        "workpackage1_tracked_diff": workpackage1_diff,
        "model_calls": 0,
        "poc_executions": 0,
        "scope": "Static file, protocol, syntax and helper checks only; no model call, network request, PHP or POC execution",
    }
    if args.report:
        target = args.report if args.report.is_absolute() else ROOT / args.report
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
