# 输出协议

协议版本为wp2-output-v1。三个Prompt版本共用字段，便于比较；版本差异体现在判定要求，不通过更换字段制造提升。模型只输出一个JSON对象，字符串用JSON转义，未知字段填null或空数组，不省略必需字段。

## 父样本字段

| 字段 | 类型与取值 | 含义 |
| --- | --- | --- |
| schema_version | 字符串，wp2-output-v1 | 协议版本 |
| sample_id | 字符串 | 工作包1的父样本ID |
| input_version | 字符串，当前v2 | 输入版本；与Prompt版本分开 |
| prompt_version | v1、v2或final | 本次提示词版本 |
| analysis_stage | partial或parent | 未收到全包或父样本综合输出 |
| received_packet_ids | 字符串数组 | 本次实际收到的输入包 |
| prediction | 存在候选、未检出候选或无法判定 | 模型静态判断，供后续与真实标签比较 |
| verdict | 确认、待验证或排除 | 确认要求对应运行证据，不用置信等级替代 |
| confidence | 对象，level与reason | high、medium或low及代码依据 |
| findings | 候选对象数组 | 每条含下面定义的全部字段 |
| exclusion_evidence | 位置对象数组 | 排除时给出实际防护证据 |
| missing_context | 字符串数组 | 缺失片段、运行配置、业务或框架条件 |
| risk_notes | 字符串数组 | 范围外风险，与目标漏洞分开 |
| quality_notes | 字符串数组 | 过时API等质量问题，不计作目标漏洞 |
| limitations | 字符串数组 | 本次证据能支持到什么程度 |
| runtime_evidence | 字符串数组 | 真实运行记录的路径；本次未运行时为空 |

## 每条候选字段

每条finding包含 `finding_id`、`vulnerability_type`、`locations`、`data_flow`、`principle`、`impact`、`preconditions`、`counterexamples`、`poc`。ID在同一父样本中唯一，跨包候选按路径归并。

每个location包含 `fragment_id`、`line_start`、`line_end`、`quote`。基础样本的fragment_id与sample_id相同，多文件样本用AUTH-001-D等ID。行号是该标准化代码块从1起始的局部行号；quote逐字引用对应行或其中连续子串，不能引用模型自行改写的代码。多个文件分别记录位置，不生成虚假的全局行号。

data_flow是可检查的步骤摘要数组，描述参数、过滤、存储、调用、危险操作与观察点；不要求输出隐藏思维过程。preconditions列出条件，counterexamples列出会阻止该路径的反例或配置。

## 每条POC字段

POC对象包含 `status`、`language`、`code`、`artifact_path`、`dependencies`、`parameters`、`steps`、`expected_observation`、`success_criteria`、`limitations`、`execution_status`。

- status为可直接运行、需人工适配或不提供。无运行环境时通常是需人工适配，不能仅凭语法正确写成已可运行。
- 模型原始响应中的code应为完整脚本文本或null，不使用省略号代替核心代码。artifact_path是同时保存的草案相对仓库路径或null，不能引用不存在文件。人工结构化整理稿可以将code设为null并引用实际完整文件，但必须注明这是整理稿，不能声称模型原文直接输出了该脚本。
- dependencies、parameters、steps、limitations均为字符串数组；预期现象和成功条件为字符串。
- execution_status为未运行或已运行。已运行必须在父对象runtime_evidence中引用实际证据；模型生成脚本本身不是运行证据。
- 没有候选时findings可以为空，不强造攻击POC；排除理由与回归观察方法仍要说明。

## 状态与证据门槛

high表示输入、关键操作、相关防护和业务路径的静态证据完整；medium表示有关键候选，但存在条件或依赖缺口；low表示仅有检查线索，不足以建立路径。不是百分比概率，也不代表实测成功。

只有已收到全部输入包才能使用analysis_stage=parent。partial输出的prediction为无法判定、verdict为待验证；可以记录包内候选，不能进入父样本指标。

存在候选通常配合verdict=待验证。源码排除只限已覆盖的目标路径；exclusion_evidence不可为空。确认必须有真实运行证据及相同条件，不能由POC草案、HTTP状态或函数名直接升级。本仓库原始标签尚待验证，不提供给模型。

## 记录示例的使用

`trial/outputs/`中的JSON为当前会话初步分析草案，不是协议中的真实运行证明，也不是独立API调用原始响应。正式评测另存完整模型原文，结构化整理稿与原文分别保存；人工不得改好输出后再计算模型格式合规率。
