# wp2-eval-42：v1/v2/final 42 条运行批次（子代理辅助）

- 批次日期：2026-10-19（UTC+08:00）
- 输入：工作包1 v2；Prompt：`prompts/prepared/{v1,v2,final}/`（逐字使用）
- 样本：14 个父样本 × 3 个 Prompt 版本 = 42 条记录
- 模型：DeepSeek Harness subagent (deepseek-flash)；模型快照、采样参数与用量不可取得，记为 unknown
- 运行方式：每条记录一个独立子代理上下文；多包样本（SQLI-005、XSS-005、AUTH-001）把同一父样本的全部包放在同一上下文一次提供，未严格逐包追加。
- 运行提示：仅补充“位置行号取代码块内 1 起始行号”的操作说明；未修改审计 Prompt 内容、样本或判定门槛。
- 保存的是子代理的最终 JSON 响应，不是 token 级流式原文；未在事后修改字段。
- 原始输出：`raw_outputs/<sample>__<version>.json`；结构化副本：`structured_outputs/`
- 严格检查：`checks/static_protocol.json` 与分版本报告
- 指标：`metrics.csv`；说明：`metrics_notes.md`；逐样本对照：`comparison.csv`
- 正式表：`prompts/evaluation_records.csv` 的 42 条记录已填为 `completed`
- 运行协议与偏差：`run_protocol.md`
- 预试验：`attempts/` 保留 1 次行号误用的试跑，不计入 42 条

## 指标

| 版本 | n | TP/FP/FN/TN/U | Accuracy | Precision | Recall | F1 | 严格协议 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| v1 | 14 | 12/0/0/2/0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 5/14 |
| v2 | 14 | 12/0/0/2/0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 8/14 |
| final | 14 | 12/0/0/2/0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 4/14 |

## 限制

- 不是正式 API 评测：模型服务端快照、采样参数和用量不可取得，不能与商业 API 结果等同。
- 子代理与人工验证执行者同属一个模型家族，且执行者已接触人工证据；本批次不是独立人工盲评。
- 多包样本一次性提供，不等同于严格逐包追加；该偏差在每条记录 notes 中注明。
- 公开靶场、14 个父样本的小样本结果不能外推真实业务系统。
- 模型 POC 未执行，`poc_result=not_run`；严格静态协议通过只说明字段、引用和 Python 语法可机械核验。
- 严格协议失败按原样保留，不修改原始输出换取通过；42 条中 25 条失败：23 条为 `vulnerability_type` 带括号/子类型（如 `XSS（反射型）`、`SQL注入（二阶）`），2 条为 `limitations` 不是字符串数组。修复版本见 `prompts/prepared/final-wp4-v2/` 与 `results/batches/wp4-final-wp4-v2/`。
