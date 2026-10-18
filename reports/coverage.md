# 覆盖统计 / Coverage

> 由 `rules.py report` 从数据库生成。覆盖 = 已**导入并通过转换**的规则，不代表对真实流量的检出率。

## 类别 × 语言（启用的规则数）

| 类别 | zh | en | mixed | any | 合计 |
|---|---|---|---|---|---|
| data_exfiltration_instruction | 1 | 12 | 1 | 0 | 14 |
| instruction_hijacking | 2 | 29 | 0 | 0 | 31 |
| instruction_override | 0 | 28 | 4 | 0 | 32 |
| jailbreak | 0 | 112 | 3 | 0 | 115 |
| obfuscated_injection | 0 | 37 | 1 | 6 | 44 |
| prompt_injection | 1 | 34 | 2 | 0 | 37 |
| role_spoofing | 1 | 29 | 1 | 0 | 31 |
| safety_bypass | 0 | 28 | 2 | 0 | 30 |
| system_prompt_extraction | 0 | 16 | 2 | 0 | 18 |

## 来源 × 状态

| 来源 | enabled | disabled | deprecated | deleted |
|---|---|---|---|---|
| atr | 312 | 2 | 2 | 0 |
| fevzi_pidr | 16 | 0 | 0 | 0 |
| trans_pid | 11 | 0 | 0 | 0 |
| manual | 13 | 0 | 0 | 0 |

## 测试样例覆盖

- 启用规则 352 条；无正例 0 条；无负例 0 条。
- 测试样例验证状态（Python 参考 oracle，**不是 C++ 引擎**）: {'python_oracle_ok': 3504, 'skipped_scope': 46, 'unverified': 309}
- 样例类型: {'known_gap': 309, 'negative': 1733, 'positive': 1817}（known_gap 为上游记录的已知绕过，不作为通过/失败断言）
- 样例来源: {'manual': 132, 'upstream': 3727}

## 未解决的问题（rule_issues）

- source_excluded (info): 524
- partial_conversion (info): 13
