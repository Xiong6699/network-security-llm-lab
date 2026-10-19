# 适配稿索引

本目录不重复保存适配脚本，避免与可执行脚本产生两份不一致副本。适配稿的实际路径、哈希、级别和修改说明见：

- `verification/adaptations/adaptation_log.csv`
- `verification/tools/run_sqli.py`
- `verification/tools/run_sqli005.py`
- `verification/tools/run_xss.py`
- `verification/tools/run_cmd.py`
- `verification/tools/run_auth.py`
- `verification/tools/browser/browser_xss.js`

模型原稿的完整代码已从原始响应抽取到 `verification/pocs/original/<batch>/<version>/`，索引为 `verification/pocs/original/poc_index.csv`。原稿与适配稿分别统计，不能把适配后脚本回算为模型原稿成功。
