# 工作包4 POC验证与结果优化报告

编制日期：2026-10-19  
适用项目：网络安全大实验 `network-security-llm-lab-main`  
批次：`wp4-poc-01`、`wp4-baseline-final`、`wp4-final-wp4-v1`、`wp4-final-wp4-v2`  
时区：UTC+08:00  
执行与复核：wp4-agent（原单人复核）+ 独立盲评子代理（17 条运行，17/17 判断一致；仍非人工小组成员签字）

## 1. 实验目的与范围

本工作包把工作包1的 14 个父样本、工作包2的冻结 Prompt 和工作包3的判定矩阵落到可复核的本地实测：搭建固定提交的完整靶场，建立人工参考标签，适配并执行 POC，保存请求/响应/浏览器/数据库证据，完成模型输出现状对照，并做一轮由实测问题驱动的 Prompt 优化与同条件复测。

范围限定为：

- 14 个父样本：SQLI-001/002/003/005、XSS-001 至 XSS-005、CMD-001 至 CMD-004、AUTH-001。
- 本地 DVWA `127.0.0.1:9080` 与 SQLi-Labs `127.0.0.1:9081`。
- 不新增正式样本、不训练模型、不开发完整审计引擎、不访问公网目标。

本报告以设计文档第 2.2 节的“最小闭环”规模为主：final 的 14 个父样本基线 + final-wp4-v1 的 14 个父样本复测 + final-wp4-v2 的 14 个父样本修正复测。另有 `wp2-eval-42` 的 42 条 v1/v2/final 运行（14 父样本 × 3 版本），由独立上下文的 DeepSeek Harness 子代理生成，已填入 `prompts/evaluation_records.csv` 并标记 `completed`；它不是正式商业 API 快照，模型快照、采样参数和用量均不可取得，因此不能等同于正式 API 横向评测。

## 2. 数据流与交付结构

```text
工作包1 v2 输入包（14 父样本 / 17 包）
        │
        ├── 人工参考标签：按工作包3矩阵逐路径/条件实测（17 条运行）
        │        └── verification/validation_log/*.json + evidence/<run_id>/
        │
        └── 模型批次：final 与 final-wp4-v1（各 14 父样本，独立上下文）
                 └── results/batches/<batch>/raw_outputs、comparison、metrics
                          │
                          └── 配对比较 → results/optimization_report.md
```

证据分层：

- `verification/`：环境、范围、runbook、POC 适配、逐次运行证据、完整性检查。
- `results/batches/wp4-poc-01/`：人工标签、POC 指标、失败归因。
- `results/batches/wp4-baseline-final/`：final 模型批次与分类指标。
- `results/batches/wp4-final-wp4-v1/`：优化版模型批次与版本对比。
- `results/change_requests.csv`、`results/optimization_report.md`：优化闭环。

## 3. 环境、固定源码与恢复

| 项目 | 实际值 |
| --- | --- |
| 宿主 | Windows 11 Build 26200 + WSL2 Ubuntu 22.04.5 |
| DVWA | 提交 `068d974487a297c155c48722f9fcf7180a83adc4`，PHP 8.1.2 |
| SQLi-Labs | 提交 `e96f21776372c8613a7e565106e62bc01a59355e`，PHP 5.6.40（ext/mysql） |
| 数据库 | MariaDB 10.6.23，本机独立 schema `dvwa`、`security` |
| 浏览器 | Chrome 155.0.8059.82 headless（playwright-core 1.64.1） |
| POC | Python 3.10.12 标准库；Node 24.16.0 仅用于浏览器证据 |
| 服务 | PHP 内置服务器，仅监听 127.0.0.1:9080/9081 |

固定源码与部署副本的 33 个关键文件逐一比较 SHA-256，全部一致；本地差异只有 DVWA `config/config.inc.php`、PHP 5.6 `php.ini`、数据库账号/schema 与内置服务器启动参数。没有修改审计源码的过滤、SQL、角色判断、输出编码或 Token 逻辑。详见 `verification/manifests/source_checksums.json`。

专用对象：

- `wp4target`（AUTH 更新目标，执行后删除）。
- `wp4v`、`wp4s' OR id=<victim_id>#`（SQLI-005 正常/攻击账号，执行后删除）。
- `wp4x5`、`wp4x5h`（XSS-005 专用留言，按 name 定向删除）。

恢复结果：`dvwa.users=5`、`dvwa.guestbook=1`（默认 test）、`security.users=13`；无残留专用对象。详见 `verification/cleanup_checklist.md`。

## 4. 人工参考标签与实测方法

### 4.1 判定口径

- `prediction`：模型静态判断（存在候选/未检出候选/无法判定）。
- `ground_truth`：人工在限定路径和条件下实测的参考标签（有漏洞/无所关注漏洞/证据不足）。
- `trigger_result`：本次运行实际观察（触发/未触发/无法判定）。
- TP/FP/FN/TN 只在同一路径、条件、完整父输出且人工标签确定时计算。

确认证据按类型区分：

- SQL：正常行、真条件行与假条件空行/报错对照，证明查询语义被改变。
- XSS：最终 HTML 位置 + 真实浏览器 DOM 执行标记，反射本身不算执行。
- 命令注入：`<pre>` 命令输出区域出现独立标记，且排除页面反射。
- 权限越权：低权限会话实际读取受保护数据，或更新后通过独立数据库/管理员路径回查。

### 4.2 全量结果

17 条运行覆盖 14 个父样本；条件级结果如下（父标签按主条件聚合）：

| 父样本 | 主条件/路径 | 运行结果 | 父标签 |
| --- | --- | --- | --- |
| SQLI-001 | Less-1 GET id | 真/假布尔差分成立 | 有漏洞 |
| SQLI-002 | Less-11 POST uname | 注释截断绕过口令，恒假无行 | 有漏洞 |
| SQLI-003 | Less-25 GET id | `&&` 绕过 or/AND 黑名单 | 有漏洞 |
| SQLI-005 | Less-24 注册/登录/改密 | 二阶注入改掉专用 victim 口令 | 有漏洞 |
| XSS-001 | xss_r low | 浏览器执行标记 | 有漏洞 |
| XSS-002 | xss_r medium | `<script>` 被替换但 `<svg onload>` 执行 | 有漏洞 |
| XSS-003 | xss_r high | 正则不覆盖 `<svg onload>`，执行 | 有漏洞 |
| XSS-004 | xss_r impossible + token | 编码输出、无执行；缺 token 为 302 | 无所关注漏洞 |
| XSS-005 | xss_s low 写/读 | 落库、再次读取、浏览器执行 | 有漏洞 |
| CMD-001 | exec low | `;` 追加 printf，标记在命令输出 | 有漏洞 |
| CMD-002 | exec medium | `|` 管道绕过 `&&`/`;` 黑名单 | 有漏洞 |
| CMD-003 | exec high | 无空格 `|` 绕过 `'| '` 替换 | 有漏洞 |
| CMD-004 | exec impossible + token | 四段数值校验，非法 IP 被拒绝 | 无所关注漏洞 |
| AUTH-001 | authbypass 页面/读取/更新 | low/medium/high 越权；impossible 拒绝 | 有漏洞 |

AUTH-001 条件矩阵：

| 条件 | 页面 | 读取接口 | 更新接口 | 结论 |
| --- | --- | --- | --- | --- |
| 普通用户 low | 200 | 返回全部 6 行，含专用对象 | ok，DB 回查变化 | 读+写越权 |
| 普通用户 medium | 403 | 返回全部行 | ok，DB 回查变化 | 读+写越权（页面拒绝不覆盖 API） |
| 普通用户 high | 403 | Access denied | ok，DB 回查变化 | 仅更新越权，读写保护不一致 |
| 普通用户 impossible | 403 | Access denied | fail，无 DB 变化 | 条件内拒绝 |
| 管理员 | 200 | 返回全部行 | ok，回查后恢复 | 合法对照 |

这说明“页面有检查”不能证明独立 API 有检查，也不能把 high 的读取拒绝推广为更新拒绝。

## 5. 模型实验协议与结果

### 5.1 协议

- 模型：DeepSeek Harness 子代理，模型标识 `deepseek-flash`；服务端快照、采样参数、用量不可取得，记为 unknown。
- 接口：DSH 子代理独立上下文；不是正式模型 API 调用记录。
- 输入：工作包1 v2；Prompt：`prompts/prepared/final/` 与 `prompts/prepared/final-wp4-v1/`。
- 每个父样本新建上下文；多包样本把 P1/P2(/P3) 一次性提供给同一子代理，未严格模拟逐包追加。这是与正式协议的主要偏差。
- 未向模型提供人工标签、POC 证据、难度名称、工作包3样本结论或验证结果。
- 原始输出原样保存在 `raw_outputs/`；结构化副本仅做字段校验，未人工改写 JSON/行号/POC。模型 POC 的完整代码另抽取到 `verification/pocs/original/<batch>/<version>/`，索引为 `poc_index.csv`，并保持“模型原稿 / 人工适配稿”分开统计。

### 5.2 基线结果（final，14 个父样本）

| 指标 | 数值 |
| --- | --- |
| TP / FP / FN / TN / U | 12 / 0 / 0 / 2 / 0 |
| Accuracy | 14/14 = 1.0000 |
| Precision | 12/12 = 1.0000 |
| Recall | 12/12 = 1.0000 |
| F1 | 24/24 = 1.0000 |
| FPR / FDR | 0/2 = 0.0000 / 0/12 = 0.0000 |
| 基础字段合规 | 14/14 |
| 严格静态协议（check_outputs.py） | 5/14；失败 9 个，主要是 `vulnerability_type` 使用带括号子类型、CMD-003 行号越界 |
| 评分覆盖率 | 14/14 |

按类型：SQL 注入 4/4、XSS 4/5 阳性 + 1 阴性正确、命令注入 3/4 阳性 + 1 阴性正确、权限越权 1/1 阳性。AUTH-001 的两个 finding 分别覆盖读取与更新，路径覆盖为 read+update。

该结果不能解释为“模型在真实代码上达到 100%”：样本只有 14 个、来源公开且集中、Prompt 直接给出代码，记忆偏差与同源难度版本无法排除。基线也没有 FP/FN 可供优化，因此优化轮的目标不是提升分类指标。

### 5.3 优化与复测（final → final-wp4-v1）

问题来源是 POC 适配与观察，而不是模型分类错误：SQL POC 只报告哈希/长度、XSS 只报告反射、AUTH 只测读取、Token 复用、存储 payload 超过 `maxlength=50`、命令标记未区分输出与反射、二阶注入缺多阶段流程。对应 7 条 POC/上下文变更请求与 `final-wp4-v1` 的 7 条“POC 运行证据补充要求”；严格协议退步另行登记 CR-008。

复测结果：

| 项目 | 基线 | 优化版 |
| --- | --- | --- |
| 分类 TP/FP/FN/TN/U | 12/0/0/2/0 | 12/0/0/2/0 |
| Accuracy | 1.0000 | 1.0000 |
| 基础字段合规 | 14/14 | 14/14 |
| 严格静态协议（check_outputs.py） | 5/14 | 4/14（格式退步） |
| POC 证据契约评分（12 个正例） | 40/47 | 45/47 |
| 提升/退步/不变 | — | 5 / 0 / 7 |
| 负例排除证据条数 XSS-004 / CMD-004 | 4 / 7 | 3 / 5 |

分类没有变化，不能宣称 Prompt 优化提升了准确率。POC 契约在 CMD-003、SQLI-005、XSS-002、XSS-003、XSS-005 五个样本上提升；AUTH-001、CMD-001、CMD-002、SQLI-001/002/003、XSS-001 无变化，说明基线 Prompt 已覆盖这些要求。反向信号有两个：两个负例的排除证据条数从 4/7 降到 3/5；严格静态协议从 5/14 降到 4/14（`vulnerability_type` 子类型、CMD-003 `success_criteria` 类型错误）。因此本轮是“POC 契约改善 + 排除论证与格式合规退步”的混合结果，不能称为全面成功；CR-008 已由 5.4 的 `final-wp4-v2` 修正。

评分是关键词/完整性启发式，不是人工质量评分，也不代表模型 POC 实际可运行；`poc_result` 仍为 not_run。

### 5.4 严格协议与负例排除修正（final-wp4-v1 → final-wp4-v2）

CR-008 的两个问题在 `final-wp4-v2` 中显式修正：`vulnerability_type` 必须精确等于 `audit_scope`，`success_criteria`/`expected_observation` 必须为字符串，负例 `exclusion_evidence` 不得少于基线。`wp4-final-wp4-v2` 的 14 个父样本复测结果：

| 项目 | 基线 final | final-wp4-v1 | final-wp4-v2 |
| --- | --- | --- | --- |
| 分类 TP/FP/FN/TN/U | 12/0/0/2/0 | 12/0/0/2/0 | 12/0/0/2/0 |
| 基础字段合规 | 14/14 | 14/14 | 14/14 |
| 严格静态协议（check_outputs.py） | 5/14 | 4/14 | 14/14 |
| 负例排除证据条数 XSS-004 / CMD-004 | 4 / 7 | 3 / 5 | 6 / 13 |

严格协议失败的两个根因均被消除，两个负例的排除证据条数也恢复到基线以上。该结果只证明字段、引用、类型与排除证据数量可机械核验，不证明漏洞判断正确、POC 可运行或排除论证质量等同；模型仍是 DeepSeek Harness 子代理，不能替代正式 API 或人工签字。证据见 `results/batches/wp4-final-wp4-v2/`。

## 6. POC 指标与适配成本

| 指标 | 结果 | 说明 |
| --- | --- | --- |
| 父样本覆盖 | 14/14 | 每个父样本至少一条实测运行 |
| 运行记录 | 17/17 | AUTH 四条件分列 |
| 正例父样本触发 | 12/12 | 每个阳性父样本至少一条确认路径 |
| 条件级正例触发 | 14/14 | 含 AUTH low/medium/high |
| 负例回归 | 2/2 | XSS-004、CMD-004 在限定范围未触发 |
| AUTH 条件矩阵 | 4/4 | low/medium/high/impossible |
| 证据完整率 | 17/17 | request/response/observation/restore 齐全 |
| 模型 POC 生成覆盖 | 12/12 | 两个模型批次的正例都含完整 POC 代码（`poc_index.csv`）；不代表可运行 |
| 模型 POC 原稿完成率 | 待测 | 模型 POC 未直接执行；执行的是人工适配参考 POC |
| 模型 POC 端到端成功 | 待测 | 未测，不能与人工适配 POC 的 12/12 混算 |

适配成本：14 个父样本合计约 435 分钟（人工估算），其中 B 级（执行与观测补齐）3 个、C 级（验证逻辑重写/人工参考 POC）11 个。4 份 trial 草案保留原稿与哈希，适配差异见 `verification/adaptations/adaptation_log.csv`；模型原稿与人工补写脚本分别标注，不能把适配稿算作模型原稿可运行。

## 7. 代表案例

### 7.1 SQLI-005 二阶注入（Less-24）

1. 正常注册 `wp4v`，登录并正常改密，再改回，证明正常流程可用。
2. 注册攻击者用户名 `wp4s' OR id=<victim_id>#`，数据库原样保存；登录后该值进入 `$_SESSION['username']`。
3. 改密接口把 SESSION 值无转义拼入 `UPDATE users ... where username='$username'`；攻击者提交无关的 current_password，仍把 victim 口令改为 `WP4NEWPASS`，影响 1 行。
4. 独立回查：victim 旧口令登录失败、新口令登录成功；攻击者口令未被修改。
5. 定向删除两个专用账号，不触碰预置管理员。

证据：`verification/evidence/wp4-20261019-sqli005-low/`。

### 7.2 AUTH-001 high：读取拒绝但更新仍可越权

页面 403、读取接口 `Access denied`，但更新接口返回 `ok`，DB 中 `wp4target.first_name` 从 `Wp4` 变为 `Wp4High`，随后恢复。说明页面检查、读取检查、更新检查的覆盖范围不同；只测读取会把该条件误判为“已防护”。

证据：`verification/evidence/wp4-20261019-auth001-high/`。

### 7.3 XSS-004 impossible：Token + 输出编码

同会话取得 token 后请求，响应中出现 `&lt;svg`/`&quot;`，无原始 `<svg`；浏览器无 `window.__wp4xss` 标记。缺失 token 返回 302，属于前置条件失败，不能当作编码生效。

证据：`verification/evidence/wp4-20261019-xss004-impossible/`。

### 7.4 CMD-003 high：无空格管道绕过

`127.0.0.1|printf WP4_CMD_003` 中的 `|` 后无空格，绕过只替换 `'| '` 的黑名单；`<pre>` 中只出现 `WP4_CMD_003`，且该标记不在页面其他位置，证明是命令输出而非反射。

证据：`verification/evidence/wp4-20261019-cmd003-high/`。

## 8. 失败归因

本批次没有模型 FP/FN，因此没有“模型判断错误”可归因；失败主要发生在 POC/观测/环境层：

| 类别 | 数量 | 代表问题 | 处理 |
| --- | --- | --- | --- |
| script | 3 | SQLI-003 用 `||` 导致假条件仍命中；XSS-005 payload 被 50 字符截断；XSS-004 导航等待超时 | 改用 `&&`、42 字符 payload、commit 等待并重跑 |
| observation | 2 | 用静态文案判断旧口令失效；CMD-004 正常 IP 被误标为 reflected | 解析会话用户名；阴性以非法 IP 拒绝/无 marker 为准 |
| environment | 2 | DVWA setup token 引号匹配；AUTH `user_id` 无默认值 | 修脚本正则；取 MAX+1 插入专用对象 |
| authentication | 0 | — | 所有会话/Token 前置条件均通过 |
| context | 0 | 14 个样本均有完整输入包；模型侧列出缺外围上下文，但不影响本地实测 | 保留为后续补充项 |
| reasoning | 0 | — | — |

失败记录与处理见 `results/batches/wp4-poc-01/failure_analysis.csv`。脚本失败与环境失败均未转成模型误报标签。

## 9. 结论与限制

### 9.1 可以支持的结论

- 在固定提交、指定条件与本地环境中，12 个父样本存在已确认的目标漏洞；XSS-004 与 CMD-004 在已测路径/条件下未取得漏洞证据。
- AUTH-001 的读取与更新保护不一致：low/medium 读写均越权，high 仅更新越权，impossible 读写均拒绝。
- SQLI-005 的二阶注入链成立：注册转义在 INSERT 时被消费，登录把原始用户名写入 SESSION，改密无转义拼接。
- final 与 final-wp4-v1 的模型分类结果相同（14/14）；优化版提升的是 POC 证据契约（40/47 → 45/47），但严格静态协议从 5/14 退到 4/14，负例排除证据条数也下降，因此不能称为全面优化成功。
- `final-wp4-v2` 在分类不变的前提下把严格静态协议从 4/14 修正到 14/14，并把 XSS-004/CMD-004 的 `exclusion_evidence` 从 3/5 恢复到 6/13（基线 4/7）；这支持“CR-008 已修复”，不支持“漏洞判断能力提升”。
- 17 条单次运行完成独立盲评，触发判断与条件标签均为 17/17 一致；该盲评由独立子代理完成，盲的是原复核结论和正式标签，不是人工小组成员签字。

### 9.2 不能支持的结论

- 不能外推为真实业务系统或整个 DVWA/SQLi-Labs 的安全状况；负例只覆盖已测路径与配置。
- 不能声称工作包2的 v1/v2/final 三版“正式 API”比较完成；42 条记录已运行并填入正式表，但模型来源是 DeepSeek Harness 子代理，快照、采样参数和用量未知，不能当作商业 API 成绩。
- 不能把 DeepSeek Harness 子代理批次当成正式 API 评测；模型快照、采样参数、用量未知，且与人工验证并非完全独立。
- 不能把 POC 契约评分当作模型 POC 可运行率；模型 POC 未直接执行。
- 不能把 17/17 盲评一致当作人工独立复核；盲评仍是同一模型家族的子代理，且证据包保留了路径与难度信息。
- 不能把负例排除证据条数恢复当作论证质量自动等价；条数是机械计数，内容仍需人工复核。

### 9.3 后续清单

1. 由人工小组成员抽查盲评分歧与 4 个代表案例；当前 17/17 一致但仍需签字确认。
2. 用用户指定的正式模型/API 重跑 42 条 v1/v2/final 记录；当前 `wp2-eval-42` 已运行并保留，可作为子代理对照批次，不能替换为正式 API 成绩。
3. `final-wp4-v2` 已明确负例排除证据最小条数与严格字段类型；后续如再改 Prompt，另开版本和新批次，保留 `wp4-final-wp4-v2`。
4. 严格协议失败已在 `wp4-final-wp4-v2` 复测为 14/14；保留基线 5/14、v1 4/14 作为退步对照（CR-008）。
5. 补充 AUTH 匿名/缺失/非法 security Cookie 条件，核查完整 `dvwaPageStartup` 初始化。
6. 若时间允许，补 XSS-005 impossible 读取对照与 SQLI-005 预置管理员不受影响的额外回查。

## 10. 证据索引与复现

| 内容 | 位置 |
| --- | --- |
| 范围声明 | `verification/scope.md` |
| 环境档案 | `verification/environment.md` |
| 运行手册 | `verification/runbook.md` |
| 清理检查 | `verification/cleanup_checklist.md` |
| 逐次运行日志 | `verification/validation_log/` |
| 请求/响应/浏览器/截图 | `verification/evidence/` |
| POC 适配与差量 | `verification/adaptations/adaptation_log.csv` |
| 模型 POC 原稿索引 | `verification/pocs/original/poc_index.csv` |
| 静态协议检查 | `results/batches/wp4-baseline-final/checks/static_protocol.json`、`results/batches/wp4-final-wp4-v1/checks/static_protocol.json`、`results/batches/wp4-final-wp4-v2/checks/static_protocol.json` |
| 用例计划与状态 | `verification/cases/case_plan.csv` |
| 源码/部署哈希 | `verification/manifests/source_checksums.json` |
| 实验清单 | `verification/manifests/experiment_manifest.json` |
| 证据完整性 | `verification/checks/evidence_integrity.json` |
| 人工标签与 POC 指标 | `results/batches/wp4-poc-01/`（含 `review_log.csv`、`review_log_single_person.csv`） |
| 17 条运行独立盲评 | `verification/blind_review/`（`blind_review.csv`、`report.md`、`key.csv`、`packets/`、`results/`） |
| final 基线批次 | `results/batches/wp4-baseline-final/` |
| final-wp4-v1 批次 | `results/batches/wp4-final-wp4-v1/` |
| final-wp4-v2 修正批次 | `results/batches/wp4-final-wp4-v2/` |
| 42 条 v1/v2/final 运行批次 | `results/batches/wp2-eval-42/`；正式表 `prompts/evaluation_records.csv` |
| 优化报告 | `results/optimization_report.md` |
| 变更请求 | `results/change_requests.csv` |

复现入口：

```bash
cd '/mnt/c/Users/zay10/Desktop/websecurity proj/network-security-llm-lab-main/verification/tools'
python3 run_sqli.py --case all
python3 run_sqli005.py
python3 run_xss.py --case all   # 先跑浏览器脚本或在已有 browser.json 后运行
python3 run_cmd.py --case all
python3 run_auth.py --level all
python3 build_results.py
python3 build_manifests.py
python3 check_evidence.py
```

浏览器证据：

```powershell
cd 'C:\Users\zay10\Desktop\websecurity proj\network-security-llm-lab-main\verification\tools\browser'
node browser_xss.js
```

完整步骤、健康检查、常见问题见 `verification/runbook.md`。
