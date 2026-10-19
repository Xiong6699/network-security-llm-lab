# final-wp4-v2 Prompt 变体

本目录由 `verification/tools/build_final_wp4_v2.py` 从 `final-wp4-v1` 生成，共 17 份逐包 Prompt。

## 改动

只新增 CR-008 的严格协议与负例排除条款：

1. `vulnerability_type` 必须精确等于审计范围（`SQL注入`、`XSS`、`命令注入`、`权限越权`），不得带括号、子类型或英文别名。
2. `success_criteria` 与 `expected_observation` 必须是单个字符串，不得输出数组。
3. 负例 `exclusion_evidence` 至少 4 条位置证据；基线已有 7 条的 CMD-004 不得少于 7 条。
4. 输出前自检字段、类型、精确类型值与负例证据条数。

输入代码、包顺序、输入版本和判定门槛不变。`prepared/manifest.json` 的主 v1/v2/final 条目也不变；本变体使用自己的 `manifest.json`。

## 复测

`results/batches/wp4-final-wp4-v2/`：14/14 严格协议通过，XSS-004/CMD-004 的 `exclusion_evidence` 为 6/13。详见该批次 README 与 `checks/cr008_verification.json`。

## 限制

仍是 DeepSeek Harness 子代理辅助批次，不是正式 API 或人工独立复核；严格协议通过不等于漏洞判断正确或 POC 可运行。
