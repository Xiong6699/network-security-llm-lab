# POC 验证

本目录保存工作包4的本地环境、POC 适配、逐次运行证据与完整性检查。当前批次 `wp4-poc-01` 已覆盖 14 个父样本、17 条条件/路径运行；证据均在 `evidence/<run_id>/`，逐次记录在 `validation_log/`。17 条运行已完成独立子代理盲评，结果见 `blind_review/`（17/17 触发与标签一致）。

## 从哪里开始

1. [范围声明](scope.md)：授权边界、样本范围、主要条件、不做的事。
2. [环境档案](environment.md)：WSL2、PHP/MariaDB、固定提交、账号对象、健康检查。
3. [复现手册](runbook.md)：从空环境到 POC、浏览器证据、结果表与清理。
4. [清理检查](cleanup_checklist.md)：专用对象、会话、仓库与服务的最终状态。
5. [用例计划](cases/case_plan.csv) 与 [实验清单](manifests/experiment_manifest.json)。
6. [证据完整性](checks/evidence_integrity.json)：17/17 通过，未发现未脱敏会话值。
7. [独立盲评](blind_review/report.md)：17 条 `single_person_review_only` 运行的脱敏复核与一致率；仍非人工签字。

## 目录

| 路径 | 内容 |
| --- | --- |
| `evidence/<run_id>/` | 脱敏请求、响应、观察、恢复、浏览器 JSON/截图 |
| `validation_log/<run_id>.json` | 单次运行的结构化记录 |
| `pocs/original/<batch>/<version>/` | 从模型原始响应抽取的完整 POC 代码，索引见 `poc_index.csv` |
| `pocs/adapted/` | 适配稿索引；实际脚本在 `tools/`，不保存重复副本 |
| `adaptations/adaptation_log.csv` | 原稿/适配稿哈希、级别、差异与耗时 |
| `manifests/` | 源码/部署哈希、实验清单 |
| `cases/case_plan.csv` | 计划条件、实际触发与状态 |
| `blind_review/` | 17 条运行的脱敏盲评包、结果、映射键、对比表与报告 |
| `tools/` | POC、浏览器、结果、盲评包与完整性脚本 |

不要提交登录 Cookie、实际密码、令牌或未脱敏敏感响应。模型批次的说明见 `../results/batches/`。

三项最终状态可只读核验：

```powershell
python verification/tools/verify_final_state.py
```

预期 `status=passed`：42 条评测记录、17 条盲评、`final-wp4-v2` 严格协议 14/14、两个负例排除证据恢复。
