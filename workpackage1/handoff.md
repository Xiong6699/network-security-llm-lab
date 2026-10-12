# 工作包 1 交接

提示词组读取 llm_inputs/，固定 v1 输入后保存模型名称、实际版本、调用日期、Prompt 版本、样本 ID 和完整输出。不要将人工核验标签或难度名称传给模型；需要外部上下文时由人工根据 metadata 选择相应函数，并记录追加内容。

推理组读取 preprocess_rules、line_maps 和 context，建立输入来源、过滤、危险操作和业务条件的判定依据。DVWA $html 的拼接需要外围 page['body'] 与 dvwaHtmlEcho 渲染路径支持；token 检查依赖认证开关和会话，不能仅凭调用名推断完整实现。

v2 增加 SQLI-005、XSS-005、AUTH-001 多文件流程。按 sample_metadata 中的 packets 顺序使用关联输入，保留父样本ID，不把26个片段统计成26个独立漏洞。具体关系与长度见 representative_cases.md。SQLI-005使用Linux部署；AUTH-001按页面与独立接口分别检查普通用户/admin及不同配置；XSS-005需要写入和再次访问两阶段证据。


DVWA 需登录、选择与 metadata 对应的难度，必要时从页面获取当前 token。记录操作系统、PHP/数据库版本、shell、ping、shell_exec 配置和浏览器条件。审计片段不能直接作为独立 Web 页面运行。

## 返回反馈

| 字段 | 内容 |
| --- | --- |
| sample_id | 样本编号 |
| input_version | 例如 v1，追加上下文另注明 |
| environment | 系统、PHP、数据库、难度、认证和 token |
| llm_verdict | 模型原始结论 |
| poc_result | 成功、失败、无法运行、证据不足 |
| ground_truth | 人工确认有漏洞／无所关注漏洞／待确认 |
| evidence_path | 脚本、输出、截图或运行日志的相对路径 |
| preprocessing_issue | 缺失入口、校验、依赖或映射问题 |
| requested_change | 要补充或修订什么 |

POC失败不直接视作误报；环境错误、脚本错误与漏洞判断错误分别记录。不能用单个POC失败证明安全。未确认样本的结果单独记录。

串行交接前检查差异、提交并推送 main；接手者先拉取。当前包未自动提交或推送，交接时由成员检查后执行。
