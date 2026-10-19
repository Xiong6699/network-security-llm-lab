# 工作包4 复现与运行手册（Runbook）

适用批次：`wp4-poc-01`  
环境：Windows 11 + WSL2 Ubuntu 22.04  
最后更新：2026-10-19

本文假设仓库位于：

```text
C:\Users\zay10\Desktop\websecurity proj\network-security-llm-lab-main
```

在 WSL 中对应：

```text
/mnt/c/Users/zay10/Desktop/websecurity\ proj/network-security-llm-lab-main
```

所有靶场目录、数据库与 PHP 运行时位于 WSL 的 `/srv`、`/opt`，不写入仓库。

## 0. 前置检查

```bash
wsl -l -v
wsl -d Ubuntu-22.04 -u root -- bash -lc "whoami; uname -a; nproc; free -h"
```

需要 WSL2、可用的 `root`（`wsl -u root` 不需要 Linux 口令）、可访问 GitHub 与 Ubuntu 软件源。若 `sudo` 需要口令，可直接使用 `wsl -u root`；不要把口令写入脚本。

## 1. 安装系统依赖

```bash
wsl -d Ubuntu-22.04 -u root -- bash -lc "
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq mariadb-server php8.1-cli php8.1-mysql php8.1-mbstring \
    php8.1-gd php8.1-xml php8.1-curl php8.1-zip build-essential libxml2-dev \
    libssl-dev pkg-config unzip ca-certificates
"
```

## 2. 取得固定提交的完整源码

```bash
wsl -d Ubuntu-22.04 -u root -- bash -lc "
  mkdir -p /srv/source_projects && cd /srv/source_projects
  rm -rf DVWA sqli-labs
  git init -q DVWA && cd DVWA
  git remote add origin https://github.com/digininja/DVWA.git
  git fetch -q --depth 1 origin 068d974487a297c155c48722f9fcf7180a83adc4
  git checkout -q FETCH_HEAD
  cd /srv/source_projects
  git init -q sqli-labs && cd sqli-labs
  git remote add origin https://github.com/Audi-1/sqli-labs.git
  git fetch -q --depth 1 origin e96f21776372c8613a7e565106e62bc01a59355e
  git checkout -q FETCH_HEAD
  git rev-parse HEAD
"
```

SQLi-Labs 的大小写冲突文件只在 Linux ext4 工作树中保留；不要把完整工作树复制到 Windows 文件系统。

## 3. 编译 PHP 5.6（SQLi-Labs 的 ext/mysql）

```bash
wsl -d Ubuntu-22.04 -u root -- bash -lc "
  curl -sSL -o /tmp/php-5.6.40.tar.gz https://museum.php.net/php5/php-5.6.40.tar.gz
  cd /srv && rm -rf php-5.6.40 && tar xzf /tmp/php-5.6.40.tar.gz
  cd php-5.6.40
  ./configure --prefix=/opt/php56 --with-config-file-path=/opt/php56/etc \
    --with-mysql=mysqlnd --with-mysqli=mysqlnd --with-pdo-mysql=mysqlnd \
    --enable-mbstring --without-openssl --without-pear --disable-cgi \
    CFLAGS='-O2 -fcommon'
  make -j20 && make install
  /opt/php56/bin/php -v
  /opt/php56/bin/php -m | grep -Ei 'mysql|session|mbstring'
"
```

`php.ini` 与 `mysql.default_socket=/run/mysqld/mysqld.sock` 由 `env_setup.sh` 写入。若 MariaDB socket 不同，先用 `mariadb -N -e 'select @@socket'` 确认。

## 4. 部署并初始化两套靶场

```bash
wsl -d Ubuntu-22.04 -u root -- bash -lc "
  sed -i 's/\r$//' '/mnt/c/Users/zay10/Desktop/websecurity proj/network-security-llm-lab-main/verification/tools/env_setup.sh'
  bash '/mnt/c/Users/zay10/Desktop/websecurity proj/network-security-llm-lab-main/verification/tools/env_setup.sh'
"
```

脚本会：

1. 把源码复制到 `/srv/web/dvwa`、`/srv/web/sqli-labs`；
2. 写入 DVWA 本地 `config/config.inc.php` 与 PHP 5.6 `php.ini`；
3. 创建 `dvwa` schema/账号，启动 MariaDB；
4. 启动 9080/9081 两个 PHP 内置服务器；
5. 运行 DVWA `setup.php` 与 SQLi-Labs `setup-db.php`；
6. 校验 `dvwa.users=5`、`security.users=13`。

预期最后一行：`ENV_SETUP_OK`。

## 5. 健康检查

```bash
# SQLI-001 正常
curl -s 'http://127.0.0.1:9081/Less-1/?id=1' | grep -o 'Your Login name:[^<]*'

# DVWA 登录页
curl -s -o /dev/null -w '%{http_code}\n' 'http://127.0.0.1:9080/login.php'

# 数据库计数
wsl -d Ubuntu-22.04 -u root -- bash -lc "mariadb -N -e 'SELECT COUNT(*) FROM dvwa.users; SELECT COUNT(*) FROM security.users'"

# ping/printf 可用
wsl -d Ubuntu-22.04 -u root -- bash -lc "ping -c 1 127.0.0.1 >/dev/null && echo PING_OK; command -v printf"
```

健康检查通过标准见 `verification/environment.md` 第 6 节。若某项失败，先修环境，不进入漏洞判断。

## 6. 运行 POC 验证

在 WSL 中执行，九条命令可分批运行：

```bash
cd '/mnt/c/Users/zay10/Desktop/websecurity proj/network-security-llm-lab-main/verification/tools'
python3 run_sqli.py --case 001
python3 run_sqli.py --case 002
python3 run_sqli.py --case 003
python3 run_sqli005.py
python3 run_xss.py --case 001
python3 run_xss.py --case 002
python3 run_xss.py --case 003
python3 run_xss.py --case 004
python3 run_xss.py --case 005
python3 run_cmd.py --case 001
python3 run_cmd.py --case 002
python3 run_cmd.py --case 003
python3 run_cmd.py --case 004
python3 run_auth.py --level low
python3 run_auth.py --level medium
python3 run_auth.py --level high
python3 run_auth.py --level impossible
```

说明：

- `run_sqli005.py` 是独立脚本，不能写成 `run_sqli.py --case 005`。
- 每个脚本都会写入 `verification/evidence/<run_id>/` 和 `verification/validation_log/<run_id>.json`。
- `run_auth.py` 会创建/重建 `wp4target`，每个条件更新后立即恢复；批次结束后还需删除该对象（见第 9 节）。
- `run_xss.py` 依赖 `browser_xss.js` 已经生成的 `browser.json`/`browser.png`；先跑浏览器（第 7 节）再跑 `run_xss.py`，或在 XSS 脚本中只做 HTTP 检查后补跑。

## 7. 浏览器执行证据（XSS）

```powershell
cd 'C:\Users\zay10\Desktop\websecurity proj\network-security-llm-lab-main\verification\tools\browser'
npm install --no-audit --no-fund
node browser_xss.js
```

脚本会启动本机 Chrome（headless），复用已登录 DVWA 会话，依次验证：

- XSS-001 low、XSS-002 medium、XSS-003 high：`window.__wp4xss` 标记必须为真；
- XSS-004 impossible：有效 Token 下输出编码、无执行；缺 Token 返回 302；
- XSS-005 low：写入专用留言、再次读取、标记执行。

输出：`verification/evidence/wp4-20261019-xss00X-*/browser.json` 与 `browser.png`。

若浏览器启动失败，确认 Chrome 路径：

```powershell
Test-Path 'C:\Program Files\Google\Chrome\Application\chrome.exe'
```

`browser_xss.js` 中 `CHROME` 常量可按实际安装位置调整。

## 8. 生成结果表、清单与证据检查

```bash
cd '/mnt/c/Users/zay10/Desktop/websecurity proj/network-security-llm-lab-main/verification/tools'
python3 build_results.py
python3 build_manifests.py
python3 check_evidence.py
```

模型批次还需要严格协议检查（在仓库根目录执行）：

```bash
cd '/mnt/c/Users/zay10/Desktop/websecurity proj/network-security-llm-lab-main'
python3 prompts/tools/check_outputs.py results/batches/wp4-baseline-final/raw_outputs \
  --report results/batches/wp4-baseline-final/checks/static_protocol.json
python3 prompts/tools/check_outputs.py results/batches/wp4-final-wp4-v1/raw_outputs \
  --report results/batches/wp4-final-wp4-v1/checks/static_protocol.json
python3 verification/tools/apply_strict_check.py
```

`check_outputs.py` 的严格检查会因 `vulnerability_type` 子类型、行号越界或 `success_criteria` 类型错误而失败；这些失败必须保留，不能用基础字段检查覆盖。

输出：

- `results/batches/wp4-poc-01/ground_truth.csv`
- `results/batches/wp4-poc-01/metrics.csv`
- `results/batches/wp4-poc-01/failure_analysis.csv`
- `results/batches/wp4-poc-01/metrics_notes.md`
- `verification/manifests/source_checksums.json`
- `verification/manifests/experiment_manifest.json`
- `verification/checks/evidence_integrity.json`

`check_evidence.py` 应报告 `runs_failed=0`、`missing_parents=[]`、`unredacted_secret_hits=0`。

## 9. 模型批次（可选/单独批次）

本仓库的 `results/batches/wp4-baseline-final/` 为 DeepSeek Harness 子代理按冻结 final Prompt 生成的辅助批次，不是正式 API 评测。若要替换为指定模型：

1. 为每个父样本新建独立上下文；
2. 按 `prompts/prepared/final/` 的包顺序输入；
3. 原样保存响应，不修改 JSON/行号/POC；
4. 用 `prompts/tools/check_outputs.py` 做静态协议检查（注意其版本白名单只接受 v1/v2/final）；
5. 把 `model_name`、`model_version`、`model_parameters`、`run_date`、`prompt_bundle_sha256` 写入 `model_runs.csv`；
6. 用同一 ground truth 生成 comparison/metrics，不要混入本辅助批次。

## 10. 清理与停止

```bash
wsl -d Ubuntu-22.04 -u root -- bash -lc "
  mariadb -N -e \"DELETE FROM dvwa.users WHERE user='wp4target'\"
  mariadb -N -e \"DELETE FROM dvwa.guestbook WHERE name IN ('wp4x5','wp4x5h')\"
  mariadb -N -e \"DELETE FROM security.users WHERE username='wp4v' OR username LIKE 'wp4s%'\"
  mariadb -N -e 'SELECT COUNT(*) FROM dvwa.users; SELECT COUNT(*) FROM dvwa.guestbook; SELECT COUNT(*) FROM security.users'
"
```

预期：`dvwa.users=5`、`dvwa.guestbook=1`（默认 test 留言）、`security.users=13`。

停止服务器：

```bash
wsl -d Ubuntu-22.04 -u root -- bash -lc "
  kill \$(cat /srv/wp4/pids/dvwa.pid) \$(cat /srv/wp4/pids/sqli.pid) 2>/dev/null || true
  fuser -k 9080/tcp 9081/tcp 2>/dev/null || true
  service mariadb stop
"
```

若需保留现场供复核，可不停止，但应在报告中说明服务仍在运行。

## 11. 复现一个代表案例（AUTH-001 high 更新）

```bash
cd '/mnt/c/Users/zay10/Desktop/websecurity proj/network-security-llm-lab-main/verification/tools'
python3 run_auth.py --level high
cat ../evidence/wp4-20261019-auth001-high/observation.json
```

预期观察：

- 普通用户页面 403；
- 普通用户读取接口返回 `Access denied`；
- 普通用户更新接口返回 `result=ok`，DB 中 `wp4target.first_name` 变为 `Wp4High`，随后恢复为 `Wp4`；
- 管理员页面/读取正常。

这与 AUTH-001 的“页面检查、读取检查、更新检查覆盖不同”结论对应。

## 12. 常见问题

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| `mysql_connect(): No such file or directory` | PHP 5.6 socket 路径不对 | 设置 `mysql.default_socket=/run/mysqld/mysqld.sock`，重启 9081 |
| DVWA setup POST 返回 302 空响应 | 正常重定向；不要只看响应体 | 以 `dvwa.users` 行数判断 setup 成功 |
| `page.goto` 等待 `domcontentloaded` 超时 | 页面资源/等待策略 | 浏览器脚本使用 `commit` 等待，再等待 body |
| XSS-005 不执行 | `textarea maxlength=50` 截断 payload | 使用 ≤50 字符 payload，或人工说明客户端限制 |
| 旧口令登录仍显示 logged-in 文案 | 页面静态文案总会渲染 | 解析 `<strong>` 会话用户名，不要匹配静态文案 |
| 端口被占用 | 上次服务器未退出 | `fuser -k 9080/tcp 9081/tcp` 后重跑 `env_setup.sh` |
