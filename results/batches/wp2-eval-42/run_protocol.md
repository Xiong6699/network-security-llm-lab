# wp2-eval-42 运行协议与偏差

## 固定条件

| 项目 | 实际值 |
| --- | --- |
| 输入 | 工作包1 v2（14 父样本、17 逐包输入） |
| Prompt | `prompts/prepared/v1/`、`prompts/prepared/v2/`、`prompts/prepared/final/`，逐字使用 |
| 模型 | DeepSeek Harness 子代理，模型标识 `deepseek-flash` |
| 模型快照/采样参数/用量 | 不可取得，记为 unknown |
| 日期 | 2026-10-19（UTC+08:00） |
| 上下文 | 每条记录一个独立子代理上下文；不同 Prompt 版本不共享上下文 |
| 原始输出 | `raw_outputs/<sample>__<version>.json`，未修改 |
| 结构化副本 | `structured_outputs/`，仅做缩进格式化，不人工改写字段、行号或引文 |

> 说明：保存的是子代理的最终 JSON 响应，不是 token 级流式原文；子代理可能在校验后写入最终对象。这里不把它称为逐 token 原始响应，也不在事后修改字段来提高合规率。

## 逐条运行方式

- 单包样本：子代理只读取对应的 `prompts/prepared/<version>/<sample>.md`。
- 多包样本：SQLI-005 读取 P1→P2，AUTH-001 读取 P1→P2→P3；全部包在同一上下文一次提供，要求模型综合为 `analysis_stage=parent` 的单个父样本 JSON。这与“严格逐包追加”存在偏差，已在每条记录 notes 中注明。
- 运行提示只补充一条操作说明：`line_start`/`line_end` 取审计数据代码块内 1 起始行号，不取 Prompt 文件行号。该说明不改变审计判断、样本、Prompt 内容或判定门槛。
- 子代理被要求不读取标签、trial、results、验证证据或其它模型输出，不使用公开靶场记忆。

## 预试验与重跑

`attempts/SQLI-001__v1.attempt1.json` 是第一次试跑，模型把 Prompt 文件行号当成代码块行号，严格检查失败；正式记录改用带行号澄清的独立重跑结果，原试跑保留但不计入 42 条。除此之外没有因分类或格式失败而重跑。

## 检查
```powershell
python prompts/tools/check_outputs.py results/batches/wp2-eval-42/raw_outputs `
  --report results/batches/wp2-eval-42/checks/static_protocol.json
```

严格检查只覆盖字段、包 ID、局部行号、逐字引文和 Python 语法。42 条中 17 条通过；25 条失败：23 条 `vulnerability_type` 带括号/子类型，2 条 `limitations` 不是字符串数组。原始输出保留，不通过修改输出来提高合规率。

## 不能声称的内容

- 不能当作正式商业 API 成绩：服务端快照、采样参数、用量均未知。
- 不能当作人工独立复核：子代理与验证执行者同属一个模型家族，且执行者已接触人工证据。
- 不能把 14/14 分类结果外推到真实业务代码；样本公开、量小、Prompt 直接给出代码，记忆偏差无法排除。
- 模型 POC 未执行，`poc_result=not_run`。
