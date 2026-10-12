# 工作包 1 使用说明

本工作包按总章程模块1整理代码来源、清洗规则、切片策略、标准输入和输出成果。当前包含11个基础样本及3个流程样本，合计14个父样本、26个代码片段。最长关联流程450行，按完整处理器和函数分包。样本数量及目录是具体实施选择，不是章程新增要求。

优先阅读 [典型样本与实际切片演示](representative_cases.md)，然后从 SQLI-005-P1.md、SQLI-005-P2.md 观察跨阶段数据流。

## 从哪里开始

1. 打开 `samples.csv`，确认每个样本的来源、版本和入口。
2. 打开 `llm_inputs/SQLI-001.md`，查看标准输入实例；对照 `raw_samples/SQLI-001.php`、`normalized_samples/SQLI-001.php` 和 `line_maps/SQLI-001.csv`。
3. 阅读 `preprocess_rules.md`，理解哪些内容删除、哪些内容保留。
4. 查看 `review_log.csv` 与 `checks/verification.json`，了解本次静态抽查和可追溯性检查；组员可增加独立复核记录。
5. 提示词组用 `llm_inputs/` 开展审计；验证组按 `sample_metadata/` 与 `handoff.md` 搭建环境并反馈。

## 文件用途

| 文件或目录 | 用途 | 是否直接交给模型 |
| --- | --- | --- |
| samples.csv | 完整样本台账 | 否 |
| normalized_samples/ | 无行号前缀的 PHP 审计片段 | 是 |
| llm_inputs/ | 标准输入实例；源难度名称已隐藏 | 是 |
| sample_metadata/ | 来源、原行号、依赖、转换及局限 | 人工选择相关字段 |
| line_maps/ | 每个标准化行到原始行的映射 | 通常由人工使用 |
| context/ | 外围处理器、渲染及 token 等完整依赖源码 | 按需选择；不要整包盲目粘贴 |
| evaluation_private/ | 后续人工确认的真实标签 | 否 |
| provenance/ | 上游版本、许可与说明 | 否 |
| review_log.csv | 实际静态抽查记录 | 否 |
| tools/ | 可复现构建与完整性核验 | 否 |

`evaluation_private` 只是用途分区，Git 协作者仍能访问。不要将整个仓库提供给待评估模型，避免模型从原始文件、路径、难度名或候选标签获取答案。原始来源仍完整保存在台账中。

## 样本安排

| ID | 人工追溯来源 | 选样目的 |
| --- | --- | --- |
| SQLI-001 | SQLi-Labs Less-1 | GET 字符串拼接 |
| SQLI-002 | SQLi-Labs Less-11 | POST 双参数登录查询 |
| SQLI-003 | SQLi-Labs Less-25 | 本地黑名单函数与调用链 |
| XSS-001 至 XSS-004 | DVWA xss_r 四档源码 | 直接输出、替换过滤、正则过滤、输出编码 |
| CMD-001 至 CMD-004 | DVWA exec 四档源码 | 直接拼接、黑名单、复杂黑名单、数字校验 |
| SQLI-005 | SQLi-Labs 注册、登录、改密及连接 | 250行跨阶段数据流，2包 |
| XSS-005 | DVWA 留言写入与读取 | 150行存储与输出流程，1包 |
| AUTH-001 | DVWA 页面、前端、API与身份渲染 | 450行权限流程，3包 |


## 复现

完整源码位于小组仓库外的 `../source_projects/`（相对于本仓库根目录）。分别克隆上游后确保固定提交对象存在，再在本仓库根目录执行：

```powershell
python workpackage1/tools/build_samples.py
python workpackage1/tools/verify_samples.py
```

Python 脚本只依赖标准库。构建脚本会重建派生文件；请先提交或保存人工编辑，已有人工标签、证据、运行状态和抽查记录保留，仅为新样本初始化记录。检查脚本不运行漏洞、网络请求或 PHP 代码。

SQLi-Labs 含 Less-24/40 大小写冲突文件，Windows 完整工作树可能不忠实；新增SQLI-005使用Less-24中的精确路径，原始文件通过 `git show 提交号:路径` 提取。完整靶场部署优先使用 Linux 并记录环境。未检测到本机 PHP 命令，本次没有执行 `php -l` 或 POC。

## 待完成

- 验证组部署固定版本并记录 PHP、数据库、操作系统、认证、难度与 token 状态。
- 每个样本实测后回填标签及证据路径；Prompt 迭代使用同一套输入。
- 参考 `docs/module1_design.md` 整合报告，补充后续修订数据。
