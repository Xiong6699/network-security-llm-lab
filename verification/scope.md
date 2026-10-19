# 工作包4 验证范围声明（wp4-poc-01）

编制日期：2026-10-19  
时区：UTC+08:00  
批次：`wp4-poc-01`  
执行人：wp4-agent（原单人执行与复核；后由独立盲评子代理完成 17 条运行的脱敏盲评，仍非人工小组成员签字）

## 1. 授权与边界

本批次的全部请求只发送到本机 WSL2 中部署的两个本地教学靶场：

- DVWA：`http://127.0.0.1:9080`
- SQLi-Labs：`http://127.0.0.1:9081`

不访问公网目标，不进行回连，不扫描非计划端口，不读取靶场以外的数据。测试仅用于课程实验的漏洞验证，不构成对任何真实业务系统的测试授权。

## 2. 样本范围

覆盖工作包1的 14 个父样本，不新增正式样本：

| 类型 | 父样本 | 覆盖路径 |
| --- | --- | --- |
| SQL 注入 | SQLI-001、SQLI-002、SQLI-003、SQLI-005 | Less-1 GET、Less-11 POST、Less-25 GET、Less-24 注册/登录/改密链 |
| XSS | XSS-001 至 XSS-005 | xss_r low/medium/high/impossible、xss_s low 写入与 low 读取 |
| 命令注入 | CMD-001 至 CMD-004 | exec low/medium/high/impossible |
| 权限越权 | AUTH-001 | authbypass 页面、读取接口、更新接口；low/medium/high/impossible |

AUTH-001 的四个安全等级属于同一父样本的不同条件，不增加父样本数。SQLI-005 的 2 个输入包、AUTH-001 的 3 个输入包和 XSS-005 的跨阶段流程按父样本归并。

## 3. 主要条件集合

- AUTH-001：普通用户 `gordonb`、`security=low`、读取与更新专用对象 `wp4target`。
- XSS-005：`security=low` 写入、`security=low` 再次读取。
- 其余 DVWA 样本：按元数据对应档位（XSS-001 low、XSS-002 medium、XSS-003 high、XSS-004 impossible、CMD-001 low、CMD-002 medium、CMD-003 high、CMD-004 impossible）。
- SQLi-Labs 无 security 概念，按各 Less 的原始入口执行。

AUTH-001 的 medium/high/impossible 作为条件补充，不混入主条件集合的父样本计数，但单独报告路径级结果。

## 4. 明确不做的事

- 不修改审计源码的过滤、SQL、角色判断或输出编码来“让 POC 成功”。
- 不枚举或导出数据库，不读取敏感文件，不建立外部连接。
- 不修改 DVWA 预置管理员口令，不删除全部留言，不使用 `TRUNCATE guestbook`。
- 不把审计片段直接当独立页面部署；全部测试使用固定提交的完整源码。
- 不把脚本运行成功、HTTP 200、页面反射、`result=ok` 或一次失败当成漏洞结论。
- 不在本批次计算模型准确率；模型批次见 `results/batches/wp4-baseline-final/`，且明确标注其模型来源与局限。

## 5. 数据处理

- 所有测试账号、对象和留言均为本批次专用，执行后删除或恢复。
- 请求证据不保存原始 `Cookie`、`Set-Cookie` 值；证据检查中未发现未脱敏会话值。
- 数据库中的测试口令只用于本地一次性账号，不写入证据；证据只保留口令哈希或“已改变”布尔值。
- 证据目录只保留复核所需的脱敏请求/响应、观察 JSON 和浏览器截图。

## 6. 复核与限制

本批次原为单人执行与单人复核，`review_status` 初始为 `single_person_review_only`。17 条运行随后由独立子代理在只看到脱敏证据、不知道原判断和正式标签的条件下完成盲评，触发判断与条件标签均为 17/17 一致；原单人记录保留在 `review_log_single_person.csv`，合并记录在 `review_log.csv`。该盲评仍是模型辅助复核，不是人工小组成员签字。结论只适用于上述提交、路径、角色、配置和本地环境，不推广为整个应用安全，也不外推真实业务系统。

模型侧的 `wp4-baseline-final` 与 `wp4-final-wp4-v1` 批次由 DeepSeek Harness 子代理在独立上下文中按冻结 Prompt 生成，模型快照与采样参数不可取得，且与人工验证并非完全独立；两个批次在结果目录中单独标注，不冒充正式 API 评测。优化版还出现严格静态协议退步与负例排除证据下降，已在优化报告中列为混合结果。
