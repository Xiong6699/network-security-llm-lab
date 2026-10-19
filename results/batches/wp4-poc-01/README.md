# wp4-poc-01：人工参考标签与 POC 批次

本批次只包含人工参考标签、运行证据与 POC 指标，不包含正式模型输出。模型侧结果在：

- `../wp4-baseline-final/`：final Prompt，14 个父样本。
- `../wp4-final-wp4-v1/`：优化版 Prompt，14 个父样本。

## 文件

| 文件 | 用途 |
| --- | --- |
| `ground_truth.csv` | 17 条运行的路径/条件标签与父标签 |
| `review_log.csv` | 合并复核记录：17 条已完成独立盲评，触发/标签 17/17 一致 |
| `review_log_single_person.csv` | 原单人复核记录备份 |
| `failure_analysis.csv` | 脚本/观测/环境问题及处理 |
| `metrics.csv` | POC 覆盖率、触发、阴性回归、证据完整率 |
| `metrics_notes.md` | 分母、排除项、未计算项与复现说明 |

## 统计口径

- 14 个父样本、17 条条件/路径运行。
- 12 个正例父样本、2 个负例父样本。
- AUTH-001 的 low/medium/high 为条件级阳性，impossible 为条件级阴性，不增加父样本数。
- 模型 `poc_result` 不在本批次；模型 POC 未直接执行，不能把人工适配 POC 算作模型原稿成功。

总报告见 `../../../docs/module4_report.md`。17 条运行的独立盲评见 `../../../verification/blind_review/report.md`；盲评是子代理辅助复核，不是人工签字。
