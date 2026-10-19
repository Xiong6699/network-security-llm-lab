# 模型批次说明（wp4-baseline-final）

## 批次性质

- 模型：DeepSeek Harness 子代理，模型标识 deepseek-flash；服务端快照、采样参数与用量不可取得，记为 unknown。
- 接口：DSH 子代理独立上下文，不是模型 API 的正式调用记录。
- 每个父样本新建上下文；多包样本把 P1/P2(/P3) 一次性提供给同一子代理，未严格模拟逐包追加，比较时需保留这一限制。
- Prompt：`prompts/prepared/final/` 冻结版本；输入版本 v2；未向模型提供人工标签、POC 证据、难度名或工作包3结论。
- 原始输出保存在 `raw_outputs/`，未做人工修正；`structured_outputs/` 为通过基础字段检查的副本。

## 指标

- 计划父样本 14；可评分 14；基础字段合规 14；严格静态协议见文末；U=0。
- TP=12、FP=0、FN=0、TN=2。
- Accuracy=1.0000，Precision=1.0000，Recall=1.0000，F1=1.0000。
- FPR=0.0000，FDR=0.0000。

## 解释限制

- 本批次由与验证执行者同一模型家族生成，且执行者已阅读人工证据；虽然子代理只读取 Prompt，仍不能视为严格独立盲评。
- 样本少、公开靶场、同源难度版本使记忆偏差无法排除。
- `poc_result` 统一为 not_run：模型生成的 POC 未直接执行；实际执行的是人工适配参考 POC，二者不能混算。
- 本批次可用于 WP4 内部对比和发现问题，不用于宣称 Prompt 的泛化提升。

## 严格静态协议检查

- `prompts/tools/check_outputs.py` 通过 5/14。
- 基础字段检查通过 14/14；两者不能互相替代。
- AUTH-001: Finding outside target scope
- CMD-002: Finding outside target scope
- CMD-003: Out-of-range citation: CMD-003
- SQLI-002: Finding outside target scope
- SQLI-005: Finding outside target scope
- XSS-001: Finding outside target scope
- XSS-002: Finding outside target scope
- XSS-003: Finding outside target scope
- XSS-005: Finding outside target scope
