# 工作包4 清理与恢复检查表

批次：`wp4-poc-01`  
检查日期：2026-10-19（UTC+08:00）  
检查方式：MariaDB 独立查询 + 证据扫描 + 文件状态检查

## 1. 数据库专用对象

| 项目 | 期望初始状态 | 实际状态 | 结果 |
| --- | --- | --- | --- |
| `dvwa.users` | 5 个预置用户 | 5 个（admin、gordonb、1337、pablo、smithy），`wp4target` 已删除 | 通过 |
| `dvwa.guestbook` | 仅默认 `test` 留言 | 1 行，name=`test`，无 `wp4x5` 专用留言 | 通过 |
| `security.users` | 13 个预置用户 | 13 个，无 `wp4v`/`wp4s%` 专用账号 | 通过 |
| AUTH 专用对象 | 执行后删除 | `wp4target` 已删除；更新字段曾用 DB 回查并恢复 | 通过 |
| SQLI-005 专用账号 | 执行后删除 | `wp4v`、`wp4s' OR id=<id>#` 已删除；victim 口令曾回查并恢复/删除 | 通过 |

SQLI-005 的正常流程在注入前把 victim 口令改到临时值再改回；注入后独立验证旧口令失败、新口令成功；最后删除专用账号。未修改 SQLi-Labs 预置教学用户。

## 2. 会话、口令与 Token

- 证据 `request.redacted.json` 不保存 `Cookie` 头；`response.redacted.txt` 中 `PHPSESSID`/`Auth` 已替换为 `<redacted>`。
- `check_evidence.py` 扫描结果：`unredacted_secret_hits=0`。
- 脚本中的 `admin/password` 等为 DVWA 预置教学账号与一次性本地测试口令，不是真实业务凭据；证据目录未保存明文口令。
- 浏览器 Cookie 只存在于运行时 context，未导出到仓库。
- `verification/evidence/**/browser.json` 不包含 Cookie 值。

## 3. 文件与仓库

- 未修改 `workpackage1/`、`prompts/`、`workpackage3/` 的既有文件。
- 新增内容集中在 `verification/`、`results/batches/`、`docs/module4_report.md`。
- `verification/tools/browser/node_modules/` 已由本地 `.gitignore` 忽略；不提交依赖目录。
- 未提交数据库文件、虚拟环境、会话文件、原始未脱敏响应。
- 现有根 `.gitignore` 忽略 `*.log`；本批次正式证据使用 `.json`、`.txt`、`.png`，不会被该规则误忽略。

## 4. 环境与服务

| 项目 | 状态 |
| --- | --- |
| MariaDB | 已停止（`service mariadb stop`） |
| DVWA 9080 | 已停止（`fuser -k 9080/tcp` 清理残留 worker） |
| SQLi-Labs 9081 | 已停止 |
| 会话目录 | `/srv/wp4/sessions`，不属于仓库 |
| 服务器日志 | `/srv/wp4/logs/`，不属于仓库 |

服务已停止，环境文件仍保留。复核时重新启动：

```bash
wsl -d Ubuntu-22.04 -u root -- bash -lc "
  bash '/mnt/c/Users/zay10/Desktop/websecurity proj/network-security-llm-lab-main/verification/tools/env_setup.sh'
"
```

## 5. 未完成/需人工确认的事项

- 17 条 `single_person_review_only` 运行已完成独立盲评，触发判断与条件标签均为 17/17 一致（`blind_review/report.md`）；复核人为独立子代理，仍不是人工小组成员签字。
- 正式模型 API/界面批次尚未由用户指定模型执行；`wp2-eval-42`、`wp4-baseline-final`、`wp4-final-wp4-v1` 与 `wp4-final-wp4-v2` 均为 DeepSeek Harness 子代理辅助批次，不能冒充正式 API 成绩。
- `final-wp4-v2` 已建立并复测：严格静态协议 14/14，XSS-004/CMD-004 排除证据 6/13；CR-008 已从 `open_regression` 更新为 `retested_fixed`。负例条数是机械计数，内容仍需人工复核。
- v1/v2/final 的 42 条记录已运行并标记 `completed`（`wp2-eval-42`）；分类均为 14/14，但模型快照/参数/用量不可取得，不能当作正式 API 成绩。
- 环境为 WSL2 本地教学部署，不是生产加固配置；PHP 5.6 仅用于兼容 SQLi-Labs 的 ext/mysql。
