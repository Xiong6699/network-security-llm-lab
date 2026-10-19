# wp4-final-wp4-v1：优化版 Prompt 模型批次

- 模型：DeepSeek Harness 子代理（`deepseek-flash`），与基线相同。
- Prompt：`prompts/prepared/final-wp4-v1/`（由 final 增加 POC 运行证据要求 7 条）；输入 v2；14 个父样本。
- 分类：TP=12、FP=0、FN=0、TN=2、U=0；与基线相同。
- 基础字段合规 14/14；严格静态协议 4/14（基线 5/14，格式退步；CMD-003 `success_criteria` 类型错误新增）。
- POC 证据契约（启发式）：45/47，基线 40/47；5 个样本提升，7 个不变。
- 负例排除证据条数：XSS-004 4→3、CMD-004 7→5，作为反向信号。
- 文件：`raw_outputs/`、`structured_outputs/`、`comparison.csv`、`version_comparison.csv`、`metrics.csv`、`metrics_notes.md`、`checks/static_protocol.json`。

## 结论

本轮是“POC 契约改善 + 排除论证/格式合规退步”的混合结果，不能称为全面成功。后续 `final-wp4-v2` 已处理负例排除证据最小条数与严格字段类型（CR-008），严格协议复测为 14/14，XSS-004/CMD-004 排除证据为 6/13；见 `../wp4-final-wp4-v2/`。

总报告：`../../../docs/module4_report.md`；优化报告：`../../../results/optimization_report.md`。
