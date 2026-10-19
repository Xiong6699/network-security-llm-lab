# 工作包4 优化复测报告（final → final-wp4-v1）

批次：`wp4-baseline-final` → `wp4-final-wp4-v1`  
日期：2026-10-19（UTC+08:00）  
输入：v2，不变；样本：14 个父样本，不变；模型与调用方式：DeepSeek Harness 子代理，不变。

## 1. 改动依据

基线分类结果为 14/14，没有 FP/FN，因此本轮不以“提高准确率”为目标。改动依据来自 POC 适配与观测中实际出现的问题（见 `results/change_requests.csv`）：

| change_id | 问题 | 证据 | 改动 |
| --- | --- | --- | --- |
| CR-001 | SQL POC 只报告状态/长度/哈希 | SQLI-001 适配记录 | success_criteria 必须解析业务结果区域，并做真/假/报错对照 |
| CR-002 | XSS POC 只报告反射 | XSS-001 浏览器证据 | 必须给出浏览器/DOM 执行证据，并与反射分开 |
| CR-003 | AUTH POC 只测读取 | AUTH-001 四档矩阵 | 页面/读取/更新分别判断；写操作有原值、独立回查和恢复 |
| CR-004 | Token 复用/拒绝被当作防护 | XSS-004、CMD-004 | 同会话按请求取最新 Token，失败分类为认证前置条件 |
| CR-005 | 存储 payload 超过 maxlength=50 | XSS-005 首次浏览器失败 | 适配字段长度，并在 limitations 说明 |
| CR-006 | 命令标记只在整页响应中查找 | CMD-001 | 必须解析命令输出区域并排除反射 |
| CR-007 | 二阶注入缺少多阶段流程 | SQLI-005 | 逐阶段记录会话/数据库回查和定向清理 |

`final-wp4-v1` 新增“POC 运行证据补充要求”7 条；未修改被审计代码、包顺序、输入版本或判定门槛。

## 2. 分类对比

- 基线：TP=12、FP=0、FN=0、TN=2，Accuracy=1.0000。
- 优化版：见 `results/batches/wp4-final-wp4-v1/metrics.csv`。
- 分类发生变化的样本：0 个。
- 分类提升：0 个；分类退步：0 个。

由于基线已无分类错误，本轮**不宣称** Prompt 优化提升了准确率；报告的是 POC 证据契约的变化，而不是漏洞判断准确率的变化。

严格静态协议检查（`prompts/tools/check_outputs.py`）：基线 5/14，优化版 4/14。主要失败是 `vulnerability_type` 使用带括号的子类型（如“XSS（反射型）”“SQL注入（二阶）”），不符合检查器要求的精确 `audit_scope`；优化版 CMD-003 还把 `success_criteria` 写成数组，新增一条类型错误。这是格式维度的真实退步，不能因为 POC 契约提升而忽略。

## 3. POC 证据契约评分

评分是对 `success_criteria`/`steps`/`parameters`/`limitations` 的关键词与完整性启发式检查，满分 7 项（按样本适用项裁剪），不是人工质量评分，也不代表实际执行成功。

| sample_id | 基线 | 优化版 | Δ | 路径覆盖（基线→优化） |
| --- | --- | --- | --- | --- |
| AUTH-001 | 3/4 | 3/4 | +0 | read+update→read+update |
| CMD-001 | 3/4 | 3/4 | +0 | single_path→single_path |
| CMD-002 | 4/4 | 4/4 | +0 | single_path→single_path |
| CMD-003 | 3/4 | 4/4 | +1 | single_path→single_path |
| CMD-004 | n/a | n/a | +0 | single_path→single_path |
| SQLI-001 | 4/4 | 4/4 | +0 | single_path→single_path |
| SQLI-002 | 4/4 | 4/4 | +0 | single_path→single_path |
| SQLI-003 | 4/4 | 4/4 | +0 | single_path→single_path |
| SQLI-005 | 4/5 | 5/5 | +1 | multi_stage→multi_stage |
| XSS-001 | 3/3 | 3/3 | +0 | single_path→single_path |
| XSS-002 | 2/3 | 3/3 | +1 | single_path→single_path |
| XSS-003 | 2/3 | 3/3 | +1 | single_path→single_path |
| XSS-004 | n/a | n/a | +0 | single_path→single_path |
| XSS-005 | 4/5 | 5/5 | +1 | write+read→write+read |

合计：基线 40/47，优化版 45/47。
提升样本 5 个，退步样本 0 个，不变 9 个（其中 2 个负例为 n/a；正例中提升 5、不变 7）。

负例 XSS-004、CMD-004 不要求攻击 POC，POC 契约评分记为 n/a；它们改为记录排除证据条数（基线/优化版）：XSS-004 4/3，CMD-004 7/5。负例的评分缺失不代表排除论证失败，但两条负例的排除证据条数均下降，作为本轮的反向信号单列。

## 4. 结论与限制

- 优化版把 POC 成功标准从“能运行/能看到回显”推进到“结果区域、真/假对照、独立回查、Token 新鲜度、字段长度、命令输出与反射区分”，与工作包4实测适配问题一一对应。
- 分类指标没有提升空间；不能把本轮写成“准确率提升”。如果个别样本的契约评分不变，说明基线 Prompt 已经覆盖该要求，优化条款对该样本是冗余的。
- 反向信号：两个负例的排除证据条数分别从 4→3、7→5，说明新增的 POC 条款可能挤压“排除条件”论证；下一轮应把负例排除证据的最小条数和必填字段写得更明确，而不是只增加 POC 要求。
- 格式退步：严格静态协议 5/14→4/14（`vulnerability_type` 子类型、CMD-003 `success_criteria` 类型错误）。因此本轮是“POC 契约改善 + 格式合规退步”的混合结果，不能称为全面成功；已登记 CR-008，并由后续 `final-wp4-v2` 修正（见第 5 节）。
- 本轮仍是同一模型家族、同一执行者、公开靶场小样本，不能外推泛化效果；优化版与基线使用相同输入，故不涉及输入变体混淆。
- `poc_result` 仍为 not_run：模型 POC 未直接执行；实际执行的是人工适配参考 POC。POC 契约评分不代表模型 POC 可运行率。

## 5. final-wp4-v2 修正复测

`final-wp4-v2` 只增加 CR-008 的严格类型与负例排除条款，不修改输入、代码、包顺序或判定门槛。批次 `wp4-final-wp4-v2` 的 14 个父样本结果：

| 指标 | 基线 final | final-wp4-v1 | final-wp4-v2 |
| --- | --- | --- | --- |
| 分类 TP/FP/FN/TN/U | 12/0/0/2/0 | 12/0/0/2/0 | 12/0/0/2/0 |
| 严格静态协议 | 5/14 | 4/14 | 14/14 |
| XSS-004 exclusion_evidence | 4 | 3 | 6 |
| CMD-004 exclusion_evidence | 7 | 5 | 13 |

- 严格协议失败的两个根因均被消除：所有 finding 的 `vulnerability_type` 精确等于 `audit_scope`；所有 `success_criteria`/`expected_observation` 均为字符串。
- 负例排除证据不再下降，且高于基线；但条数只证明“位置证据数量”，不证明每条论证都同等有效，仍需人工复核内容。
- 分类结果没有变化，不能宣称准确率提升；本修正只针对格式协议与负例排除证据两个已登记问题。
- 仍是 DeepSeek Harness 子代理辅助批次，不是正式 API 或人工独立复核。证据：`results/batches/wp4-final-wp4-v2/`。

