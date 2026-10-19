# 实验结果

按样本和 Prompt 版本记录模型结论、人工核验、POC 状态和证据路径。只有人工确认的真实标签用于误报漏报统计；证据不足和脚本环境失败单独汇总。

## 当前批次

| 批次 | 内容 | 入口 |
| --- | --- | --- |
| `wp4-poc-01` | 14 个父样本、17 条运行的人工标签、POC 指标与失败归因 | [ground_truth](batches/wp4-poc-01/ground_truth.csv)、[metrics](batches/wp4-poc-01/metrics.csv)、[notes](batches/wp4-poc-01/metrics_notes.md) |
| `wp2-eval-42` | v1/v2/final 各 14 个父样本，共 42 条运行记录 | [README](batches/wp2-eval-42/README.md)、[metrics](batches/wp2-eval-42/metrics.csv)、[comparison](batches/wp2-eval-42/comparison.csv) |
| `wp4-baseline-final` | final Prompt 的 14 个父样本辅助模型批次 | [comparison](batches/wp4-baseline-final/comparison.csv)、[metrics](batches/wp4-baseline-final/metrics.csv) |
| `wp4-final-wp4-v1` | final-wp4-v1 的 14 个父样本复测与版本对比 | [comparison](batches/wp4-final-wp4-v1/comparison.csv)、[version comparison](batches/wp4-final-wp4-v1/version_comparison.csv) |
| `wp4-final-wp4-v2` | CR-008 修正：严格协议 14/14、负例排除证据 6/13 | [README](batches/wp4-final-wp4-v2/README.md)、[strict check](batches/wp4-final-wp4-v2/checks/static_protocol.json) |

优化闭环见 [change_requests.csv](change_requests.csv) 与 [optimization_report.md](optimization_report.md)。模型批次均为 DeepSeek Harness 子代理辅助结果，不是正式 API 评测；严格静态协议通过数与格式退步必须与基础字段合规分开阅读。17 条运行的独立盲评见 [blind_review/report.md](../verification/blind_review/report.md)。工作包4 报告见 [module4_report.md](../docs/module4_report.md)；覆盖工作包1至4的总报告见 [final_report.md](../docs/final_report.md)。
