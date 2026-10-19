# wp4-final-wp4-v2：严格协议与负例排除修正批次

- 批次日期：2026-10-19（UTC+08:00）
- 基础：`final-wp4-v1`；输入 v2、14 个父样本、17 个逐包 Prompt 不变
- 改动：仅新增 CR-008 的严格类型与负例排除条款（见 `prompts/prepared/final-wp4-v2/manifest.json`）
- 模型：DeepSeek Harness subagent (deepseek-flash)；快照/采样参数/用量不可取得
- 保存的是子代理的最终 JSON 响应，不是 token 级流式原文；未在事后修改字段
- 运行提示重复了 Prompt 中已有的 `vulnerability_type` 精确值、字符串类型和负例最小条数规则；这是执行澄清，不是额外漏洞判定信息
- 原始输出：`raw_outputs/`；结构化副本：`structured_outputs/`；严格检查：`checks/static_protocol.json`；CR-008 自动核验：`checks/cr008_verification.json`
- 分类指标：`metrics.csv`；三版对照：`comparison.csv`；负例排除条数：`negative_exclusion.csv`

## 结果

| 指标 | 基线 final | 优化版 final-wp4-v1 | 修正版 final-wp4-v2 |
| --- | --- | --- | --- |
| 分类 TP/FP/FN/TN/U | 12/0/0/2/0 | 12/0/0/2/0 | 12/0/0/2/0 |
| 严格静态协议 | 5/14 | 4/14 | 14/14 |
| XSS-004 exclusion_evidence | 4 | 3 | 6 |
| CMD-004 exclusion_evidence | 7 | 5 | 13 |

## 限制

- 仍为同一模型家族的子代理辅助批次，不是正式 API 评测，也不是人工独立复核。
- 严格协议通过只证明字段、引用、类型与 Python 语法可机械核验，不证明漏洞判断正确或 POC 可运行。
- 负例排除条数按 `exclusion_evidence` 位置对象计数；数量恢复不等于论证质量自动等价，仍需人工复核内容。
