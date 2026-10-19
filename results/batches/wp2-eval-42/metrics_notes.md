# wp2-eval-42 指标说明

## 统计范围

- 14 个父样本 × v1/v2/final = 42 条父样本级记录。
- 每条记录一个独立子代理上下文；多包样本在同一上下文一次收到全部包。
- 真实标签使用 `results/batches/wp4-poc-01/ground_truth.csv` 的父样本标签；AUTH-001 以 low 主条件为父标签，XSS-004/CMD-004 为负例。
- 预测为 `存在候选` 记阳性；`未检出候选` 记阴性；`无法判定` 单列，不进入 TP/FP/FN/TN。

## 分类指标

三版均为 TP=12、FP=0、FN=0、TN=2、U=0，Accuracy/Precision/Recall/F1 均为 1.0000。该结果只适用于这 14 个公开教学样本，不能外推真实业务代码，也不能解释为模型具备通用审计能力。

## 严格静态协议

`check_outputs.py` 同时检查字段集合、包 ID、局部行号、逐字引文、`vulnerability_type` 精确等于 `audit_scope`、`success_criteria`/`expected_observation` 类型和 Python 语法。结果：

| 版本 | 通过 | 失败原因 |
| --- | --- | --- |
| v1 | 5/14 | 9 条 `vulnerability_type` 带括号/子类型 |
| v2 | 8/14 | 6 条 `vulnerability_type` 带括号/子类型 |
| final | 4/14 | 8 条 `vulnerability_type` 子类型，2 条 `limitations` 类型错误 |

合计 17/42 通过、25 条失败：23 条 `vulnerability_type` 子类型，2 条 `limitations` 不是字符串数组。原始输出保留，不通过修改 JSON 提高合规率。修复版本 `final-wp4-v2` 的复测为 14/14，见 `results/batches/wp4-final-wp4-v2/`。

## 不能计算/不能声称

- 不能计算 POC 可运行率：模型 POC 未执行，`poc_result=not_run`。
- 不能计算真实误报率/漏报率：样本量小、标签只覆盖已测路径，且无独立人工盲评；这里的 14/14 只是与已有父标签的一致率。
- 不能声称 Prompt 因果提升：三版分类相同，严格协议差异是格式维度；没有随机化、没有独立 API 快照。
- 不能把子代理最终 JSON 当作 token 级原始响应；保存的是最终对象，未做字段修正。
