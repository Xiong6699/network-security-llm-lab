"""Build de-identified blind-review packets for the 17 single-person runs.

The reviewer packet deliberately removes run_id, sample_id, trigger_result,
ground_truth and every reviewer conclusion.  The original label key is written
to key.csv, which the reviewer prompt tells the reviewer not to read.

Run from the repository root:

    python verification/tools/build_blind_review.py
"""
from __future__ import annotations

import csv
import json
import random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LOGS = ROOT / "verification" / "validation_log"
EVIDENCE = ROOT / "verification" / "evidence"
OUT = ROOT / "verification" / "blind_review"
PACKETS = OUT / "packets"
RESULTS = OUT / "results"
SEED = 20261019


def load_json(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def truncate(text: str, limit: int = 5000) -> str:
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} characters]..."


def main() -> None:
    PACKETS.mkdir(parents=True, exist_ok=True)
    RESULTS.mkdir(parents=True, exist_ok=True)
    logs = []
    for path in sorted(LOGS.glob("wp4-*.json")):
        log = load_json(path)
        if log.get("review_status") != "single_person_review_only":
            continue
        logs.append(log)
    if len(logs) != 17:
        raise SystemExit(f"expected 17 single-person runs, found {len(logs)}")

    rng = random.Random(SEED)
    rng.shuffle(logs)
    key_rows = []
    for index, log in enumerate(logs, 1):
        blind_id = f"BR-{index:02d}"
        run_id = log["run_id"]
        obs_path = EVIDENCE / run_id / "observation.json"
        req_path = EVIDENCE / run_id / "request.redacted.json"
        resp_path = EVIDENCE / run_id / "response.redacted.txt"
        obs = load_json(obs_path)
        evidence = dict(obs)
        evidence.pop("run_id", None)
        evidence.pop("sample_id", None)
        evidence.pop("artifacts", None)
        request = load_json(req_path)
        response = resp_path.read_text(encoding="utf-8", errors="replace")
        packet = f"""# 独立盲评包 {blind_id}

你是第二位独立复核人。你只看到一次本地授权靶场运行的脱敏证据，不知道原复核人的结论，也不知道样本的正式标签。不要读取仓库中的其它文件，不要根据运行编号、样本编号或公开靶场记忆猜测答案；只按下列成功标准逐条核对证据。

## 本次条件

- 路径：`{log['path_id']}`
- 条件：`{log['condition_key']}`
- 成功标准：
{chr(10).join(f'  {i}. {item}' for i, item in enumerate(log['success_criteria'], 1))}
- 已知限制：
{chr(10).join(f'  - {item}' for item in log['limitations'])}

## 脱敏观察记录

```json
{json.dumps(evidence, ensure_ascii=False, indent=2)}
```

## 请求证据

```json
{json.dumps(request, ensure_ascii=False, indent=2)}
```

## 响应证据（截断）

```text
{truncate(response)}
```

## 你的任务

1. 逐条判断成功标准是否被证据满足（true / false / unknown）。
2. 判断本次条件是否触发了目标漏洞：`触发`、`未触发` 或 `无法判定`。
3. 判断该条件的参考标签：`有漏洞`、`无所关注漏洞` 或 `证据不足`。
4. 判断证据是否足以支持该结论，并指出仍然缺少的证据。
5. 只输出一个 JSON 对象，不要 Markdown 围栏，字段如下：

```json
{{
  "blind_id": "{blind_id}",
  "trigger": "触发|未触发|无法判定",
  "condition_ground_truth": "有漏洞|无所关注漏洞|证据不足",
  "confidence": "high|medium|low",
  "evidence_sufficient": true,
  "criteria": [
    {{"criterion": "原文或摘要", "met": "true|false|unknown", "evidence": "证据依据"}}
  ],
  "rationale": "不超过 200 字",
  "missing_evidence": ["..."]
}}
```

注意：`证据不足` 与 `未触发` 不同；不能仅凭 HTTP 200、页面反射、脚本退出码或一次失败下结论。把结果写入：

`verification/blind_review/results/{blind_id}.json`
"""
        (PACKETS / f"{blind_id}.md").write_text(packet, encoding="utf-8", newline="\n")
        key_rows.append({
            "blind_id": blind_id,
            "run_id": run_id,
            "sample_id": log["sample_id"],
            "condition_key": log["condition_key"],
            "original_trigger": log["trigger_result"],
            "original_ground_truth": log["ground_truth"],
        })

    with (OUT / "key.csv").open("w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(key_rows[0].keys()))
        writer.writeheader()
        writer.writerows(key_rows)
    print(f"wrote {len(key_rows)} blind packets to {PACKETS}")


if __name__ == "__main__":
    main()
