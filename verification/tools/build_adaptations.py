"""Record POC provenance and adaptation cost for every parent sample."""
from __future__ import annotations

import csv
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "verification" / "adaptations" / "adaptation_log.csv"


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


ROWS = [
    ("SQLI-001", "prompts/trial/pocs/sqli_001.py", "verification/tools/run_sqli.py", "B",
     "保留本地地址校验/禁止重定向/正常-真-假对照；补充响应正文、登录名解析和错误文本提取。",
     "草案只输出状态/长度/哈希，无法复核SQL语义。", "wp4-agent", 20),
    ("SQLI-002", "", "verification/tools/run_sqli.py", "C",
     "使用代码实际参数 uname/passwd 重写 POST 对照；增加注释截断真值与恒假对照。",
     "无模型原稿；草案参数不适用于 Less-11。", "wp4-agent", 25),
    ("SQLI-003", "", "verification/tools/run_sqli.py", "C",
     "按源码黑名单顺序设计 && 真/假对照，保留 filtered hint。",
     "无模型原稿；需验证过滤后语义仍可控。", "wp4-agent", 25),
    ("SQLI-005", "", "verification/tools/run_sqli005.py", "C",
     "实现注册/登录/改密三阶段；专用 victim 与攻击者；数据库回查、独立登录回查、定向删除。",
     "无模型原稿；跨阶段二阶注入需要多步流程和恢复。", "wp4-agent", 70),
    ("XSS-001", "prompts/trial/pocs/xss_001.py", "verification/tools/run_xss.py", "B",
     "保留无害输入和反射检查；增加同会话浏览器执行、DOM标记、截图。",
     "反射不等于执行，草案未验证浏览器。", "wp4-agent", 25),
    ("XSS-002", "", "verification/tools/run_xss.py", "C",
     "增加 <script> 过滤对照，使用 svg onload 绕过固定字符串替换。",
     "无模型原稿；需证明过滤只覆盖固定字符串。", "wp4-agent", 20),
    ("XSS-003", "", "verification/tools/run_xss.py", "C",
     "增加 <script> 正则对照，使用不含 script 的 svg onload。",
     "无模型原稿；需证明正则作用域有限。", "wp4-agent", 20),
    ("XSS-004", "", "verification/tools/run_xss.py", "C",
     "同会话取 token；有效 token 编码输出、缺失 token 302；浏览器无执行对照。",
     "无模型原稿；Token 前置条件失败不能当作编码阻断。", "wp4-agent", 35),
    ("XSS-005", "", "verification/tools/run_xss.py", "C",
     "low 写入专用留言、DB 回查、low 再次读取、浏览器执行、按 name 定向清理。",
     "无模型原稿；存储型需要写入/持久化/读取/最终DOM四段证据。", "wp4-agent", 45),
    ("CMD-001", "prompts/trial/pocs/cmd_001.py", "verification/tools/run_cmd.py", "B",
     "保留正常/测试对照；增加 <pre> 命令输出提取、Linux 分支确认、标记反射排除。",
     "草案只检查静态标记是否出现在响应中。", "wp4-agent", 20),
    ("CMD-002", "", "verification/tools/run_cmd.py", "C",
     "按 medium 黑名单使用 | 管道载荷；保留正常 ping 与命令输出。",
     "无模型原稿；需验证 &&/; 被删后仍有可用分隔符。", "wp4-agent", 20),
    ("CMD-003", "", "verification/tools/run_cmd.py", "C",
     "按 high 黑名单使用无空格 | 载荷；对比正常 ping。",
     "无模型原稿；需验证 '| ' 过滤被无空格形式绕过。", "wp4-agent", 20),
    ("CMD-004", "", "verification/tools/run_cmd.py", "C",
     "同会话取 token；正常 IP、含分隔符非法 IP、五段 IP 三类对照。",
     "无模型原稿；阴性需要有效排除证据和 Token 分支。", "wp4-agent", 30),
    ("AUTH-001", "prompts/trial/pocs/auth_001_read.py", "verification/tools/run_auth.py", "C",
     "保留双会话/安全档位/JSON结构检查；补充更新接口、专用对象、DB回查、四档矩阵和恢复。",
     "草案只报告读取结构，不能证明越权更新；页面/读取/更新需分别核验。", "wp4-agent", 60),
]


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with open(OUT, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "sample_id", "original_source", "original_sha256", "adapted_source",
            "adapted_sha256", "adaptation_level", "changes", "rationale",
            "executor", "minutes_estimate", "notes",
        ])
        for sample, original, adapted, level, changes, rationale, executor, minutes in ROWS:
            original_path = ROOT / original if original else None
            adapted_path = ROOT / adapted
            writer.writerow([
                sample,
                original or "none (no model POC in trial)",
                sha256(original_path) if original_path and original_path.exists() else "",
                adapted,
                sha256(adapted_path),
                level,
                changes,
                rationale,
                executor,
                minutes,
                "shared adapted harness; original model POC remains unchanged in prompts/trial/pocs/"
                if original else "manual reference POC; not a model-generated artifact",
            ])
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
