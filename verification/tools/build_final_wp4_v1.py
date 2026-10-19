"""Generate the evidence-driven final-wp4-v1 prompt variant.

The change is deliberately limited to the POC runtime-evidence contract; the
audited code, packet order, input version and decision thresholds are unchanged.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "prompts" / "prepared" / "final"
DST = ROOT / "prompts" / "prepared" / "final-wp4-v1"
TZ = timezone(timedelta(hours=8))

SECTION = """
### wp4-v1 运行证据补充要求

本版本由工作包4的实测适配问题驱动，输入代码、包顺序和判定门槛不变，只补充POC可观测性与恢复要求：

1. POC必须写出目标业务结果区域或字段的解析方法，不能只记录HTTP状态码、响应长度或哈希。
2. 参数名、HTTP方法和请求路径必须来自给定代码；不得套用其他Less、其他框架或其他样本的参数。
3. 需要Token的路径必须同会话按请求获取最新Token；Token缺失或被拒绝属于前置条件失败，不能写成输出编码或过滤生效。
4. 写操作（改密、更新、存储写入）必须写出原值、独立回查路径和恢复或定向清理步骤；不能只凭接口返回ok、页面文案或数据库转义确认。
5. 客户端maxlength、隐藏按钮、菜单不可见和页面提示不作为服务端防护；载荷长度需适配实际字段限制，并在limitations中说明。
6. 命令注入必须区分命令输出区域与页面反射；SQL必须区分正常行、真条件命中行和假条件空行，不能只看报错。
7. success_criteria必须逐条对应上述观察；脚本可运行、HTTP 200、页面回显或一次失败都不能替代触发或排除证据。

本版本的输出对象中 `prompt_version` 固定为 `final-wp4-v1`；其余字段与 wp2-output-v1 相同。
"""


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def transform(text: str) -> str:
    text = text.replace("# final 父样本综合审计Prompt", "# final-wp4-v1 父样本综合审计Prompt", 1)
    text = text.replace("Prompt版本final；", "Prompt版本final-wp4-v1；")
    text = text.replace("| prompt_version | v1、v2或final |", "| prompt_version | v1、v2、final或final-wp4-v1 |")
    marker = "只输出一个JSON对象。答复前检查字段完整性、片段与行号、条件与结论是否一致；这只检查自己的输出，不等于人工核验。无候选时允许不提供攻击POC，但需给出排除证据及必要的安全回归观察方法；上下文不足时不强行编造脚本。"
    if marker not in text:
        raise RuntimeError("insertion marker not found")
    text = text.replace(marker, marker + SECTION, 1)
    return text


def main() -> None:
    DST.mkdir(parents=True, exist_ok=True)
    entries = []
    for src in sorted(SRC.glob("*.md")):
        original = src.read_text(encoding="utf-8")
        updated = transform(original)
        dst = DST / src.name
        dst.write_text(updated, encoding="utf-8")
        packet = src.stem
        sample_id = packet.rsplit("-P", 1)[0]
        entries.append({
            "sample_id": sample_id,
            "prompt_version": "final-wp4-v1",
            "packet_id": packet,
            "prompt_file": str(dst.relative_to(ROOT)).replace("\\", "/"),
            "prompt_sha256": sha256_bytes(updated.encode("utf-8")),
            "source_final_sha256": sha256_bytes(original.encode("utf-8")),
        })
    manifest = {
        "design_date": datetime.now(TZ).strftime("%Y-%m-%d"),
        "version": "final-wp4-v1",
        "base_version": "final",
        "input_version": "v2",
        "change_basis": "work package 4 POC adaptation and observation failures (hash-only SQL result, reflection-only XSS, token reuse, client maxlength truncation, AUTH read-only draft, command-output vs reflection)",
        "scope": "POC runtime evidence, token freshness, independent readback/restore, result-region parsing; no change to audited code, packet order, input version or decision thresholds",
        "entries": entries,
    }
    (DST / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "files": len(entries),
        "version": manifest["version"],
        "sample_ids": sorted({e["sample_id"] for e in entries}),
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
