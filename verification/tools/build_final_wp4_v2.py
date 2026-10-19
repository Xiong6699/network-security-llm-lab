"""Generate the strictly typed final-wp4-v2 prompt variant.

Change basis: CR-008 in results/change_requests.csv.  The variant keeps the
audited code, packet order, input version and decision thresholds of
final-wp4-v1 unchanged, and only adds explicit output-type and negative-case
exclusion-evidence requirements.  Run this from the repository root:

    python verification/tools/build_final_wp4_v2.py
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "prompts" / "prepared" / "final-wp4-v1"
DST = ROOT / "prompts" / "prepared" / "final-wp4-v2"
TZ = timezone(timedelta(hours=8))

SECTION = """
### wp4-v2 严格协议与负例排除要求

本版本只修正严格静态协议失败和负例排除证据下降，不改变被审计代码、包顺序、输入版本或判定门槛。

1. `vulnerability_type` 必须精确等于审计范围字符串本身：SQL 样本写 `SQL注入`，XSS 样本写 `XSS`，命令注入样本写 `命令注入`，权限越权样本写 `权限越权`。不得写成 `SQL注入（二阶）`、`XSS（反射型）`、`stored_xss` 等带子类型、括号、英文别名或组合值；子类型只能放在 `principle`、`impact` 或 `data_flow` 的自由文本里。
2. `success_criteria` 与 `expected_observation` 必须是单个字符串，不得输出字符串数组。需要多条时在字符串内用 `1)`、`2)`、`3)` 编号。`dependencies`、`parameters`、`steps`、`limitations` 仍为字符串数组，保持 wp2-output-v1 的其它类型不变。
3. 负例（`prediction=未检出候选`、`verdict=排除`）的 `exclusion_evidence` 至少给出 4 条位置证据；若该路径的基线记录已有 7 条（CMD-004），不得少于 7 条。每条必须引用真实 `fragment_id`、局部行号与逐字引文，并分别覆盖：输入变换或编码、认证或 token 前置条件、危险操作不可达或参数边界、观察与安全回归方法。不得因为 POC 条款而减少排除证据。
4. 输出前逐项自检：必需字段集合、字段类型、`vulnerability_type` 精确值、负例 `exclusion_evidence` 条数。自检不通过时重写输出，不得把数组或带括号的子类型原样提交。

本版本的输出对象中 `prompt_version` 固定为 `final-wp4-v2`；其余字段与 wp2-output-v1 相同。
"""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def transform(text: str) -> str:
    text = text.replace("# final-wp4-v1 父样本综合审计Prompt", "# final-wp4-v2 父样本综合审计Prompt", 1)
    text = text.replace("Prompt版本final-wp4-v1；", "Prompt版本final-wp4-v2；")
    text = text.replace("| prompt_version | v1、v2、final或final-wp4-v1 |",
                        "| prompt_version | v1、v2、final、final-wp4-v1或final-wp4-v2 |")
    text = text.replace(
        "本版本的输出对象中 `prompt_version` 固定为 `final-wp4-v1`；其余字段与 wp2-output-v1 相同。",
        "", 1)
    marker = "7. success_criteria必须逐条对应上述观察；脚本可运行、HTTP 200、页面回显或一次失败都不能替代触发或排除证据。"
    if marker not in text:
        raise RuntimeError("insertion marker not found")
    text = text.replace(marker, marker + "\n" + SECTION, 1)
    return text


def main() -> None:
    DST.mkdir(parents=True, exist_ok=True)
    entries = []
    for src in sorted(SRC.glob("*.md")):
        original = src.read_text(encoding="utf-8")
        updated = transform(original)
        dst = DST / src.name
        dst.write_text(updated, encoding="utf-8", newline="\n")
        packet = src.stem
        sample_id = packet.rsplit("-P", 1)[0]
        entries.append({
            "sample_id": sample_id,
            "prompt_version": "final-wp4-v2",
            "packet_id": packet,
            "prompt_file": str(dst.relative_to(ROOT)).replace("\\", "/"),
            "prompt_sha256": sha256_bytes(updated.encode("utf-8")),
            "source_final_wp4_v1_sha256": sha256_bytes(original.encode("utf-8")),
        })
    manifest = {
        "design_date": datetime.now(TZ).strftime("%Y-%m-%d"),
        "version": "final-wp4-v2",
        "base_version": "final-wp4-v1",
        "input_version": "v2",
        "change_basis": "CR-008: strict vulnerability_type equality, string-typed success_criteria/expected_observation, and a minimum negative-case exclusion-evidence count",
        "scope": "Strict output typing and negative-case exclusion evidence only; no change to audited code, packet order, input version or decision thresholds",
        "entries": entries,
    }
    (DST / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({
        "files": len(entries),
        "version": manifest["version"],
        "sample_ids": sorted({e["sample_id"] for e in entries}),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
