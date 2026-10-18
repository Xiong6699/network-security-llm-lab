"""Assemble fixed teaching audit inputs. No model calls or POC execution."""
from pathlib import Path
import argparse
import csv
import hashlib
import json
import re
import subprocess

ROOT = Path(__file__).resolve().parents[2]
PROMPTS = ROOT / "prompts"
DATA = ROOT / "workpackage1"
VERSIONS = ("v1", "v2", "final")
RULES = {
    "SQL注入": "sql_injection.md",
    "XSS": "xss.md",
    "命令注入": "command_injection.md",
    "权限越权": "authorization.md",
}
FIELDS = (
    "sample_id", "input_version", "prompt_version", "condition_key",
    "model_name", "model_version", "model_parameters", "run_date",
    "prompt_bundle_sha256", "raw_output_path", "structured_output_path",
    "prediction", "location_review", "poc_result", "ground_truth",
    "validation_evidence", "status", "notes",
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def read(path):
    return path.read_text(encoding="utf-8-sig")


def embed(text):
    """Keep included rules below the four main second-level sections."""
    return re.sub(r"^(#{1,4}) ", lambda m: "##" + m.group(1) + " ", text, flags=re.M)


def get_samples():
    with (DATA / "samples.csv").open(encoding="utf-8-sig", newline="") as f:
        rows = list(csv.DictReader(f))
    result = []
    for row in rows:
        meta = json.loads(read(DATA / row["metadata_file"]))
        if meta["sample_id"] != row["sample_id"]:
            raise ValueError("Sample ID differs from metadata")
        if meta["audit_scope"] not in RULES:
            raise ValueError("Unsupported audit scope")
        packets = meta.get("packets") or [{
            "packet_id": meta["sample_id"],
            "input_file": f"llm_inputs/{meta['sample_id']}.md",
            "fragment_ids": [meta["sample_id"]],
            "code_lines": meta["normalized_lines"],
        }]
        if meta.get("preprocess_version") != "v2":
            raise ValueError("This design expects work package 1 input v2")
        result.append((meta, packets))
    if len({m["sample_id"] for m, _ in result}) != len(result):
        raise ValueError("Duplicate parent sample IDs")
    return result


def build():
    samples = get_samples()
    protocol = embed(read(PROMPTS / "output_schema.md"))
    constraints = embed(read(PROMPTS / "poc_constraints.md"))
    files = {}
    entries = []
    sources = {}
    for version in VERSIONS:
        template_path = PROMPTS / "versions" / f"{version}.md"
        template = read(template_path)
        sources[template_path.relative_to(ROOT).as_posix()] = digest(template_path.read_bytes())
        for meta, packets in samples:
            sid = meta["sample_id"]
            scope = meta["audit_scope"]
            rule_path = PROMPTS / "rules" / RULES[scope]
            scenario = embed(read(rule_path)) if version != "v1" else ""
            if version != "v1":
                sources[rule_path.relative_to(ROOT).as_posix()] = digest(rule_path.read_bytes())
            for index, packet in enumerate(packets, 1):
                source_path = DATA / packet["input_file"]
                source_text = read(source_path)
                rel_source = source_path.relative_to(ROOT).as_posix()
                source_hash = digest(source_path.read_bytes())
                sources[rel_source] = source_hash
                boundary = f"AUDIT_DATA_{source_hash[:20]}"
                if boundary in source_text:
                    raise ValueError("Audit boundary collides with input")
                if index < len(packets):
                    completeness = "当前尚未收到后续全部输入包，analysis_stage=partial、prediction=无法判定、verdict=待验证，只记录本包事实与缺口。"
                else:
                    completeness = "仅在实际保有清单内全部输入包时输出analysis_stage=parent；若前包未提供或已超出上下文，保持partial并列出缺失包。"
                values = {
                    "SAMPLE_ID": sid, "INPUT_VERSION": "v2", "AUDIT_SCOPE": scope,
                    "PACKET_ID": packet["packet_id"], "PACKET_INDEX": str(index),
                    "PACKET_COUNT": str(len(packets)),
                    "PACKET_ORDER": " → ".join(p["packet_id"] for p in packets),
                    "COMPLETENESS_RULE": completeness, "SCENARIO_RULES": scenario,
                    "OUTPUT_PROTOCOL": protocol, "POC_CONSTRAINTS": constraints,
                    "INPUT_BLOCK": f"BEGIN_{boundary}\n{source_text.rstrip()}\nEND_{boundary}",
                }
                def replace(match):
                    key = match.group(1)
                    if key not in values:
                        raise ValueError(f"Unknown template field: {key}")
                    return values[key]
                body = re.sub(r"\{\{([A-Z_]+)\}\}", replace, template).rstrip() + "\n"
                out_path = f"prepared/{version}/{packet['packet_id']}.md"
                files[PROMPTS / out_path] = body.encode("utf-8")
                entries.append({
                    "sample_id": sid, "audit_scope": scope, "input_version": "v2",
                    "prompt_version": version, "packet_id": packet["packet_id"],
                    "packet_index": index, "packet_count": len(packets),
                    "fragment_ids": packet["fragment_ids"], "code_lines": packet["code_lines"],
                    "source_input": rel_source, "source_sha256": source_hash,
                    "prompt_file": f"prompts/{out_path}", "prompt_sha256": digest(files[PROMPTS / out_path]),
                    "execution_status": "not_run",
                })
    for p in (PROMPTS / "output_schema.md", PROMPTS / "poc_constraints.md", DATA / "samples.csv"):
        sources[p.relative_to(ROOT).as_posix()] = digest(p.read_bytes())
    for meta, _ in samples:
        p = DATA / "sample_metadata" / f"{meta['sample_id']}.json"
        sources[p.relative_to(ROOT).as_posix()] = digest(p.read_bytes())
    try:
        commit = subprocess.check_output(["git", "-C", str(ROOT), "log", "-1", "--format=%H", "--", "workpackage1"], text=True).strip() or None
    except (OSError, subprocess.CalledProcessError):
        commit = None
    manifest = {
        "design_date": "2026-10-13", "source_commit_for_workpackage1": commit,
        "input_version": "v2", "parent_sample_count": len(samples),
        "input_packet_count_per_version": len(entries) // len(VERSIONS),
        "prepared_prompt_count": len(entries), "versions": list(VERSIONS),
        "scope": "Prepared inputs only; not model calls or vulnerability ground truth",
        "source_sha256": sources, "entries": entries,
    }
    files[PROMPTS / "prepared" / "manifest.json"] = (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode()
    return files, manifest


def initialize_records(manifest):
    path = PROMPTS / "evaluation_records.csv"
    existing = {}
    if path.exists():
        with path.open(encoding="utf-8-sig", newline="") as f:
            previous = list(csv.DictReader(f))
        for row in previous:
            existing.setdefault((row["prompt_version"], row["sample_id"]), []).append(row)
    rows = []
    for version in VERSIONS:
        parents = sorted({e["sample_id"] for e in manifest["entries"]})
        for sid in parents:
            hashes = [e["prompt_sha256"] for e in manifest["entries"] if e["sample_id"] == sid and e["prompt_version"] == version]
            bundle = digest(json.dumps(hashes).encode())
            old_rows = existing.pop((version, sid), [])
            if old_rows:
                for row in old_rows:
                    untouched = row["status"] == "not_run" and not row["raw_output_path"] and not row["structured_output_path"]
                    if row["prompt_bundle_sha256"] != bundle and not untouched:
                        raise ValueError("Recorded experiment uses different prompts; preserve it and create a separate batch")
                    if untouched:
                        row["prompt_bundle_sha256"] = bundle
                    rows.append(row)
            else:
                rows.append({
                    "sample_id": sid, "input_version": "v2", "prompt_version": version,
                    "condition_key": "待固定", "prompt_bundle_sha256": bundle,
                    "status": "not_run", "notes": "正式评测待填；同会话试用另存trial，不回填为正式成绩",
                })
    rows.extend(row for group in existing.values() for row in group)
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Check prepared files without writing")
    parser.add_argument("--refresh", action="store_true", help="Explicitly refresh generated inputs; never edit sample files or records")
    args = parser.parse_args()
    files, manifest = build()
    mismatches = [p for p, data in files.items() if not p.exists() or p.read_bytes() != data]
    if args.check:
        if mismatches:
            raise SystemExit("Prepared inputs missing or changed: " + ", ".join(str(p.relative_to(ROOT)) for p in mismatches[:5]))
    else:
        changed = [p for p in mismatches if p.exists()]
        if changed and not args.refresh:
            raise SystemExit("Existing generated inputs differ; preserve experiment evidence and use --refresh only for a new batch")
        for p in mismatches:
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(files[p])
        initialize_records(manifest)
    print(f"PASS: {manifest['parent_sample_count']} parent samples, {manifest['input_packet_count_per_version']} packets/version, {manifest['prepared_prompt_count']} prepared prompts; no model/POC execution")


if __name__ == "__main__":
    main()
