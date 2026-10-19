# 17 条单次运行的独立盲评

本目录记录 `wp4-poc-01` 中 17 条 `single_person_review_only` 运行的独立盲评。

## 文件

| 路径 | 用途 |
| --- | --- |
| `packets/BR-01.md` … `BR-17.md` | 脱敏盲评包；不含 run_id、sample_id、原触发判断、原标签或原复核结论 |
| `results/BR-01.json` … `BR-17.json` | 独立复核人的结构化结论 |
| `key.csv` | 盲评编号到 run_id/原标签的映射；复核完成后才由脚本读取 |
| `blind_review.csv` | 盲评结论与原判断逐条对照 |
| `report.md` | 一致率、混淆矩阵、分歧与限制 |

## 方法

1. `build_blind_review.py` 从 `validation_log/`、`evidence/<run_id>/` 生成 17 个包，按固定种子 20261019 打乱编号。
2. 每个包只包含路径、条件、原成功标准、脱敏 observation、request 和 response；`trigger_result`、`ground_truth`、`review_status` 不进入包。
3. 独立复核子代理逐条判断成功标准，给出 `trigger`、`condition_ground_truth`、置信度和缺失证据。
4. `compare_blind_review.py` 读取 `key.csv`，计算一致率，更新 `results/batches/wp4-poc-01/review_log.csv`；原单人记录保存在 `review_log_single_person.csv`。

## 结果与限制

- 已完成 17/17；触发判断 17/17 一致，条件标签 17/17 一致，分歧 0。
- 盲的是原复核结论与正式标签；包内仍保留路径和难度档位，不能对样本身份完全设盲。
- 复核人为独立子代理，不是人工小组成员，不能替代人工签字。
- 证据不足的运行可能出现 `无法判定`；本次没有出现，但缺失证据仍逐条记录在 `blind_review.csv` 的 `missing_evidence` 列。

## 复现

```powershell
python verification/tools/build_blind_review.py
# 逐个把 packets/BR-xx.md 交给独立复核人，结果写入 results/BR-xx.json
python verification/tools/compare_blind_review.py
```
