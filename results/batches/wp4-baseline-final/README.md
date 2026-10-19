# wp4-baseline-final：final Prompt 模型批次

- 模型：DeepSeek Harness 子代理（`deepseek-flash`）；快照/采样参数/用量不可取得。
- Prompt：`prompts/prepared/final/`；输入 v2；14 个父样本。
- 分类：TP=12、FP=0、FN=0、TN=2、U=0；Accuracy/Precision/Recall/F1 = 1.0000。
- 基础字段合规 14/14；严格静态协议 5/14（`check_outputs.py`，主要失败为 `vulnerability_type` 子类型、CMD-003 行号越界）。
- 原始输出：`raw_outputs/`；结构化副本：`structured_outputs/`；严格检查：`checks/static_protocol.json`。
- 指标：`metrics.csv`；配对：`comparison.csv`；说明：`metrics_notes.md`。

## 限制

- 不是正式 API 评测；多包样本一次性提供，未严格逐包追加。
- 与验证执行者同一模型家族，且执行者已阅读人工证据，不能视为严格独立盲评。
- 公开靶场小样本，不能外推真实业务泛化效果。
- 模型 POC 未执行，`poc_result=not_run`。

总报告：`../../../docs/module4_report.md`。
