# 网络安全大实验

本项目记录 LLM 辅助漏洞挖掘的设计、输入样本、提示词、POC 验证和结果复盘。
流程为：代码预处理 → 提示词设计 → 漏洞分析 → 本地 POC 验证 → 结果校验与优化。

## 当前进度

工作包 1 已准备第二版 14 个父样本、26 个代码片段，覆盖 SQL 注入、XSS、命令注入、权限越权。源码版本、行号映射、人工核验标签和上下文分别保存。尚未部署靶场、运行 POC 或统计误报漏报。

从 [工作包 1 使用说明](workpackage1/README.md) 开始；提示词组使用 `workpackage1/llm_inputs/`，评估人员另看台账和候选标签。

## 目录与分工

| 目录 | 内容 | 负责人 |
| --- | --- | --- |
| workpackage1/ | 代码预处理与数据标准化 | 工作包 1 成员 |
| docs/ | 总报告材料 | 全组整合 |
| prompts/ | 提示词设计与迭代 | 工作包 2 成员 |
| verification/ | 环境、POC 和运行记录 | 验证负责人 |
| results/ | 结果校验与复盘 | 结果负责人 |

实际姓名由小组补充。模型推理模块的材料可由负责人放入 `docs/`。

## 串行协作

全组使用 `main` 分支。同一时间只有一人修改；交接人提交并推送后通知下一位；接手人在无未提交改动时运行 `git pull --ff-only origin main`。
提交前运行 `git status` 和 `git diff --cached` 检查文件。不要提交真实密码、登录 Cookie、数据库文件和本地虚拟环境。
新增样本使用唯一 ID；本实验中 ID 只表示审计范围，不表示结论。固定模型版本、输入版本和样本集后，再比较不同 Prompt。

## 样本来源

- https://github.com/Audi-1/sqli-labs
- https://github.com/digininja/DVWA

来源提交号及许可说明见 `workpackage1/provenance/` 和 `samples.csv`。上游片段保留其原有授权条件；本仓库不为上游代码重新指定统一许可证。
