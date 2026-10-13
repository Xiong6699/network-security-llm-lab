# 提示词设计

本工作包在工作包1的v2输入基础上设计通用Prompt、四类漏洞专属规则和两轮修订。输入仍为14个父样本、26个片段、17份输入包，不改写工作包1的代码、标签或映射。当前完成提示词套件和同一Codex会话的初步试用；独立模型评测、POC实测和误报漏报指标尚未完成。

## 从哪里开始

1. 阅读 [输出协议](output_schema.md) 和 [POC约束](poc_constraints.md)，区分静态候选、运行确认与人工标签。
2. 查看 [版本记录](prompt_iteration.md)，了解v1、v2、final的修改依据和证据范围。
3. 在仓库根目录运行 `python prompts/tools/prepare_inputs.py`，得到三个版本的51份逐包Prompt及固定样本清单。脚本不调用模型，不执行POC，不改动工作包1。
4. 打开 `prepared/final/SQLI-001.md` 使用完整Prompt。多包样本按清单顺序在同一实验会话追加，最后一包后再综合父样本；模型上下文不足时另记补充条件，不静默丢弃前包。
5. 查看 [初步试用](trial/README.md)、[草案对照](trial/comparison.md) 与 [评测办法](evaluation_plan.md)。保存真实模型原文后，按 [交接说明](handoff.md) 交给推理与验证人员。
6. 按 [验收清单](acceptance.md) 区分已完成设计、初步试用与仍待实测的项目。
7. 按 [测试说明](testing.md) 运行一条只读自检命令，并区分静态通过与真实漏洞验证。

## 文件用途

| 文件或目录 | 用途 | 是否直接交给模型 |
| --- | --- | --- |
| versions/ | 四段式通用模板，v1、v2及final | 经填充后使用 |
| rules/ | SQL注入、XSS、命令注入、权限越权专属判定与POC要求 | v2及final按类型选一份 |
| output_schema.md | 固定JSON字段及结论边界 | 随Prompt提供 |
| poc_constraints.md | 环境、前置条件、无害验证与判定限制 | 随Prompt提供 |
| prepared/ | 51份完整逐包Prompt；清单保存路径、顺序、哈希和版本 | 是，只选当前样本 |
| trial/ | 本会话初步分析草案、POC草案和静态检查结果 | 否，不作为后续盲测输入 |
| evaluation_plan.md | 固定条件、统计口径与评测记录办法 | 人工使用 |
| evaluation_records.csv | 42条父样本与版本的正式评测待填记录 | 否 |
| prompt_iteration.md | 两轮设计修订、观察结果及未完成事项 | 人工使用 |
| handoff.md | 工作包3、4的输入输出及反馈约定 | 人工使用 |
| tools/ | 输入组装和静态协议检查；只使用Python标准库 | 否 |

`final`表示当前设计冻结版，不表示漏洞已确认，也不表示实验性能已达到最终要求。模型配置、输入或判定规则改变后另开评测批次，不覆盖旧原文。模型评测文件不能包含人工答案、标签、难度路径或同会话试用输出。

## 检查与当前边界

```powershell
python prompts/tools/prepare_inputs.py --check
python prompts/tools/check_outputs.py prompts/trial/outputs
```

第一条检查现有组装结果与源文件一致；第二条检查JSON协议、引用行号、代码引文和POC文件关系，并对本批Python草案做语法编译。两者不运行网络请求、PHP或漏洞，不证明POC可运行率或误报率。

本会话试用不能证明独立模型能力或Prompt因果效果。完整14个父样本的正式记录仍为待评测，工作包4返回实测证据后再补充指标和必要修订。总报告材料见 [模块2设计](../docs/module2_design.md)。
