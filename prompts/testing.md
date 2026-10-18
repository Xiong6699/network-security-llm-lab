# 工作包2：怎样测试与判断

先在仓库根目录打开 PowerShell，运行只读检查。这里使用 Codex 自带的 Python；如果本机的 `python --version` 能正常显示 Python 3.9 或更新版本，也可以把 `$labPython` 换成 `python`。

```powershell
Set-Location 'C:\Users\12396\Documents\ChatGPT\26271网络安全大作业'
$labPython = 'C:\Users\12396\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe'
& $labPython 'prompts/tools/self_check.py' --report 'prompts/checks/self_check.json'
```

看到 `"status": "passed_static_checks"` 且命令退出码为0，说明本次静态自检通过。当前应看到51份组装Prompt、14个父样本、42条正式评测记录（都为`not_run`）、15份同会话草案、6个错误输出被拒绝、4份POC草案通过语法和本地地址约束检查，工作包1没有被改动。报告保存在 [self_check.json](checks/self_check.json)。若退出码不为0，读取报错中的文件或检查项，先排查源文件、Prompt或草案是否被修改；不要直接刷新覆盖已有实验记录。

也可以单独检查某一层：

```powershell
& $labPython 'prompts/tools/prepare_inputs.py' --check
& $labPython 'prompts/tools/check_outputs.py' 'prompts/trial/outputs' --report 'prompts/trial/checks.json'
```

第一条比对生成的Prompt和工作包1输入；第二条检查草案JSON字段、父样本输入包是否齐全、引用行号与代码原文是否一致、POC文件是否存在并且Python语法可编译。`passed_static_protocol`只说明输出形式和引用可核查，不说明漏洞判断正确。

## 怎样评价提示词本身

用 [评测计划](evaluation_plan.md) 的固定14个父样本分别测试v1、v2、final。每次记录真实模型名称、版本、参数、原始输出、组装Prompt哈希和条件；多包样本按顺序给齐，不能把单包判断当父样本结论。对每个候选先人工核对代码位置和数据流，再由工作包4核验；工作包1目前的`待验证`标签不能直接当作真值。

通过标准要同时看四件事：

| 项目 | 怎样判断 |
| --- | --- |
| 输出可用 | JSON符合协议，行号、代码引文、输入包和漏洞类型都对得上。 |
| 定位准确 | 指向真正的入口、关键处理和危险操作；仅有相邻行或函数名不算准确。 |
| 判断可靠 | 有可复核的前提与反证；“存在候选”与“确认”分开；经验证后再统计误报、漏报。 |
| POC可用 | 在记录的靶场版本、配置和角色下实际运行，保存请求、响应及预期观察；仅能编译或收到HTTP 200不算成功。 |

分别统计确认后的精确率、召回率、误报率，以及POC实际可运行率；未验证样本保持`待验证`，不填0也不强行归类。比较三个版本时使用相同样本和相同评测条件，并保留每版原始输出，才有资格说哪一版更好。本仓库当前的15份草案来自同一Codex会话，不能当成15次独立模型实验。

## 怎样评价POC草案

4份草案在 `prompts/trial/pocs/`。先运行例如 `& $labPython 'prompts/trial/pocs/sqli_001.py' --help` 查看参数；真正执行需要已授权、已部署的本地教学靶场，以及实际路径、会话和对应软件版本。脚本当前只限制到本地地址、收集观察；仓库内没有真实运行记录。

SQL注入要比较正常、真条件和假条件的**实际查询结果**，排除登录跳转与报错页；XSS要在浏览器确认无害标记是否真的执行，单纯回显不够；命令注入要把额外命令的可观察结果与正常请求、操作系统差异分开；权限越权要在相同配置下比较管理员和普通用户是否能读取受保护数据，HTTP状态码本身不够。验证只用教学数据和只读或无害操作。

把每次运行的环境、参数、原始观察和失败原因交给工作包4。若运行失败，先区分环境未部署、路径错误、未登录、条件不满足、脚本不兼容和确实无法触发；这些情况不能直接算作“误报”。当前 [验收清单](acceptance.md) 中的正式效果指标仍待实测。
