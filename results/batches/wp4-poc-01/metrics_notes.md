# POC 批次指标说明（wp4-poc-01）

## 统计范围

- 批次：wp4-poc-01；执行日期 2026-10-19（UTC+08:00）。
- 14 个父样本全部至少执行一次；共 17 条运行记录，其中 AUTH-001 按 low/medium/high/impossible 四个条件分别记录。
- 运行记录键为 run_id + sample_id + path_id + condition_key，证据在 `verification/evidence/<run_id>/`。
- 17 条运行的独立盲评见 `verification/blind_review/`：触发判断与条件标签均 17/17 一致；盲评由独立子代理完成，不是人工小组成员签字。

## 分母与计数

- 正例父样本 12 个：SQLI-001/002/003/005、XSS-001/002/003/005、CMD-001/002/003、AUTH-001。
- 负例父样本 2 个：XSS-004、CMD-004。
- 正例父样本 12 个均至少有一个条件/路径取得触发证据（12/12）；条件级正例运行 14 条全部触发（14/14）。
- 负例运行 2 条全部取得限定范围内的排除/回归证据（2/2）。
- AUTH-001 的 low/medium/high 条件均取得越权证据；impossible 条件下读取与更新均被拒绝，作为条件级阴性，不推翻父样本阳性。
- 证据完整率按“每个 run 均有 request/response/observation/restore 文件”单独检查，见 `verification/checks/evidence_integrity.json`。

## 未计算/不能计算

- 未计算模型 precision/recall/F1：本批次只做人工参考标签与 POC 验证，模型侧批次另列。没有正式模型输出时，不得把 trial 草案当作正式成绩。
- 未把脚本执行成功、HTTP 200、反射或 `result=ok` 当作漏洞确认；确认依据是命令输出、浏览器执行、独立数据库回查/登录回查。
- 负例只覆盖已测路径与配置，不推广为整个应用安全。

## 复现

运行 `verification/tools/` 下对应脚本，环境已记录在 `verification/environment.md`。所有测试对象均为本地专用对象，执行后删除或恢复。
