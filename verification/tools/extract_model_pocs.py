"""Extract model-generated POC code from the two model batches.

Raw output stays untouched; this only materialises the inline POC code into the
verification/pocs/original tree and records hashes for the adaptation workflow.
"""
from __future__ import annotations

import csv
import hashlib
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "verification" / "pocs" / "original"
BATCHES = {
    "wp4-baseline-final": ("final", ROOT / "results" / "batches" / "wp4-baseline-final" / "raw_outputs"),
    "wp4-final-wp4-v1": ("final-wp4-v1", ROOT / "results" / "batches" / "wp4-final-wp4-v1" / "raw_outputs"),
}


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    index = []
    for batch, (version, raw_dir) in BATCHES.items():
        for path in sorted(raw_dir.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            sample = data.get("sample_id", path.stem)
            for finding in data.get("findings", []):
                poc = finding.get("poc") or {}
                code = poc.get("code")
                if not isinstance(code, str) or not code.strip():
                    continue
                language = (poc.get("language") or "python").lower()
                suffix = ".py" if language.startswith("python") else ".txt"
                target_dir = OUT / batch / version
                target_dir.mkdir(parents=True, exist_ok=True)
                target = target_dir / f"{sample}-{finding.get('finding_id', 'F1')}{suffix}"
                target.write_text(code, encoding="utf-8")
                index.append({
                    "batch_id": batch,
                    "prompt_version": version,
                    "sample_id": sample,
                    "finding_id": finding.get("finding_id", ""),
                    "language": language,
                    "status": poc.get("status", ""),
                    "execution_status": poc.get("execution_status", ""),
                    "path": str(target.relative_to(ROOT)).replace("\\", "/"),
                    "sha256": sha256(target.read_bytes()),
                    "bytes": len(target.read_bytes()),
                })
    with open(OUT / "poc_index.csv", "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=[
            "batch_id", "prompt_version", "sample_id", "finding_id", "language",
            "status", "execution_status", "path", "sha256", "bytes"])
        writer.writeheader()
        writer.writerows(index)
    print(json.dumps({"extracted": len(index),
                      "batches": sorted({row['batch_id'] for row in index}),
                      "samples": len({row['sample_id'] for row in index})}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
