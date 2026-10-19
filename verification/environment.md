# 工作包4 本地环境档案（wp4-poc-01）

记录日期：2026-10-19  
时区：UTC+08:00  
部署标识：`dvwa-wsl-01`、`sqli-labs-wsl-01`

## 1. 主机与虚拟化

| 项目 | 实际值 |
| --- | --- |
| 宿主机 | Windows 11 专业版，Build 26200 |
| 虚拟化 | WSL2，Ubuntu 22.04.5 LTS（`yanyu`） |
| 内核 | 6.6.87.2-microsoft-standard-WSL2 x86_64 |
| 资源 | 20 vCPU，约 23 GiB 可用内存；WSL ext4 可用约 954 GB |
| 网络 | 仅本机回环；Windows 通过 WSL2 localhost 转发访问 127.0.0.1:9080/9081 |
| 浏览器 | Google Chrome 155.0.8059.82（headless） |

## 2. 运行时与数据库

| 组件 | 版本/配置 | 用途 |
| --- | --- | --- |
| MariaDB | 10.6.23-MariaDB-0ubuntu0.22.04.1 | 两个靶场共用本机实例，独立 schema |
| PHP 8.1 | 8.1.2-1ubuntu2.26，`mysqli`、`mysqlnd`、`gd`、`mbstring` | DVWA |
| PHP 5.6 | 5.6.40，源码编译，`mysql`、`mysqli`、`mysqlnd`、`pdo_mysql`、`mbstring`、`session` | SQLi-Labs（需要 ext/mysql） |
| SQLi-Labs | 提交 `e96f21776372c8613a7e565106e62bc01a59355e` | `/srv/web/sqli-labs` |
| DVWA | 提交 `068d974487a297c155c48722f9fcf7180a83adc4` | `/srv/web/dvwa` |
| Python | 3.10.12，仅标准库 | POC 与结果脚本 |
| Node.js | v24.16.0 | 浏览器证据 |
| playwright-core | 1.64.1（只驱动本机 Chrome，不下载浏览器） | XSS 执行证据 |

PHP 5.6 编译参数：

```text
./configure --prefix=/opt/php56 --with-config-file-path=/opt/php56/etc \
  --with-mysql=mysqlnd --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd \
  --enable-mbstring --without-openssl --without-pear --disable-cgi \
  CFLAGS='-O2 -fcommon'
```

`/opt/php56/etc/php.ini` 关键项：`mysql.default_socket=/run/mysqld/mysqld.sock`、`mysqli.default_socket=/run/mysqld/mysqld.sock`、`session.save_path=/srv/wp4/sessions`、`output_buffering=4096`、`date.timezone=Asia/Shanghai`。

## 3. 部署方式

两套靶场分别使用 PHP 内置 HTTP 服务器，监听本机回环：

```text
DVWA:      PHP 8.1  -S 127.0.0.1:9080 -t /srv/web/dvwa   (PHP_CLI_SERVER_WORKERS=4)
SQLi-Labs: PHP 5.6  -S 127.0.0.1:9081 -t /srv/web/sqli-labs
```

数据库：

- `dvwa` schema，用户 `dvwa`@`127.0.0.1`/`localhost`，仅该 schema 权限，另给 `CREATE` 以完成 setup。
- `security` schema，由 SQLi-Labs 自带 `sql-connections/setup-db.php` 创建并写入 13 条教学用户。
- SQLi-Labs 的 `sql-connections/db-creds.inc` 保持上游原样（`root`、空口令、unix socket），因为 PHP 5.6 服务以 root 运行且只监听回环。该配置属于本地部署差异，未修改审计源码。

DVWA 本地配置：由 `config/config.inc.php.dist` 生成 `config/config.inc.php`，数据库口令为本地一次性值，不写入仓库；默认 `default_security_level=low`，每个用例通过强制 `security` Cookie 指定实际档位；`disable_authentication=false`。

## 4. 源码一致性与部署差异

- 两个工作树在 `/srv/source_projects/` 中按固定提交检出，部署副本在 `/srv/web/`，不包含 `.git`。
- 对 33 个被审计源码/入口文件逐一比较源工作树与部署副本的 SHA-256，全部一致（见 `manifests/source_checksums.json`）。
- 本地差异只有：DVWA 的 `config/config.inc.php`、PHP 5.6 的 php.ini、内置服务器启动参数、数据库账号与 schema。没有修改过滤、SQL、角色判断、输出编码或 Token 逻辑。
- SQLi-Labs 含 Less-24/40 大小写冲突；完整工作树只保存在 Linux ext4 中，Windows 侧不复制。

## 5. 账号、角色与测试对象

| 用途 | 账号/对象 | 说明 |
| --- | --- | --- |
| DVWA 管理员 | `admin` | 预置账号，未修改口令 |
| DVWA 普通用户 | `gordonb` | 预置账号，用于 AUTH-001 越权对照 |
| AUTH 专用对象 | `wp4target`（user_id=6） | 本批次创建；只改 first_name/last_name，执行后删除 |
| SQLi-005 正常/攻击/目标 | `wp4v`、`wp4s' OR id=<victim_id>#`、专用 victim 行 | 本批次创建；执行后删除，不触碰预置管理员 |
| XSS-005 留言 | name=`wp4x5h` / `wp4x5` | 本批次专用；按 name 定点删除，未使用 btnClear/TRUNCATE |

口令只用于一次性本地账号，不写入证据或仓库；证据中的请求体已对 password 类字段脱敏。

## 6. 环境健康检查（漏洞判断之前）

| 检查 | 实际结果 |
| --- | --- |
| SQLI-001 正常 `id=1` | 返回 `Your Login name:Dumb` |
| SQLI-002 正常 `Dumb/Dumb` | 返回教学用户行与 flag 图 |
| SQLI-005 正常注册/登录/改密 | `wp4v` 注册成功；登录成功；改密成功并可回登；恢复原口令 |
| SQLI-003 正常 `id=1` | 返回 `Dumb`，过滤提示正常显示 |
| DVWA 管理员登录 | `You have logged in as 'admin'` |
| DVWA 普通用户登录 | `You have logged in as 'gordonb'` |
| xss_r 四档渲染 | low/medium/high 正常；impossible 返回 Token 输入并编码输出 |
| xss_s 写入/读取 | 专用留言落库并在再次访问时渲染 |
| exec 正常 ping | `<pre>` 中返回 4 个回包；`shell_exec`、`/usr/bin/ping`、`/usr/bin/printf` 可用 |
| exec impossible Token | 页面提供 `user_token`；缺失 Token 返回 302 |
| AUTH 管理员读取/更新 | 读取返回 6 行；更新专用对象后 DB 回查成功并恢复 |
| 证据落盘 | request/response/observation/browser/screenshot 均可写入 `verification/evidence/` |

在健康检查通过之后才执行漏洞判断；任何一项失败时对应样本保持未测并先修环境。

## 7. 浏览器与证据

- 浏览器上下文每次运行重新登录（或单会话复用），通过 `document.cookie` 设置 `security` 档位，Cookie 不写入证据。
- XSS 执行证据使用无害 DOM 标记 `window.__wp4xss`，不读取 Cookie、不外传数据。
- 截图、`browser.json`、控制台和页面错误保存在对应 `verification/evidence/<run_id>/`。
- 未使用 Burp/AWVS、未使用公网 OOB、未安装完整浏览器自动化平台。

## 8. 可复现入口

环境重建与启动脚本：`verification/tools/env_setup.sh`。  
完整步骤见 `verification/runbook.md`。  
源码与部署哈希见 `verification/manifests/source_checksums.json`。
