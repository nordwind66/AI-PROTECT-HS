# 误报评估 / False positives

> 由 `python tools/rules.py eval` 生成（2026-10-17T03:28:58Z），规则集 `1.0.0`，快照 sha256 `34e6d9afaa76ca99…`。  
> **引擎是 Python 参考实现（`refengine.py`，Python `re`），不是 Hyperscan/PCRE2 的 C++ 引擎。** 语料是人工编写的小样本且在开发规则时参考过，数字**只描述这个规则集在这些样本上的表现**，不是真实流量的误报率估计。真实评估需要 Linux 环境 + 业务脱敏流量，见 `docs/linux-testing.md`。

## 1. 人工编写的正常文本语料（`tests/corpus/benign_zh_en.jsonl` + `benign_extended.jsonl`）

- 样本 221：`alert` 3，`review` 8，`allow` 210。
- 其中**预期会被触发的“引述攻击字符串”样本**（`known_fp_risk`，正则规则无法区分引用与使用）：3 / 3。
- 其余正常样本中被标记的：**8** / 218。

| 样本 | 类别 | 决策 | 分数 | 触发规则 | 文本 |
|---|---|---|---|---|---|
| q001 | quoted_attack | alert | 0.982 | AIPS-IO-0006, AIPS-IO-0029, AIPS-JB-0004, AIPS-PI-0001 (+1) | In the paper, the authors quote the classic attack string 'ignore all… |
| q002 | quoted_attack | alert | 0.921 | AIPS-IO-0032, AIPS-PI-0009, AIPS-PI-0014 | 安全培训材料里引用了一个典型的攻击样例：“忽略之前的所有指令”，用来说明直接提示词注入是什么样子。 |
| q003 | quoted_attack | alert | 0.910 | AIPS-JB-0111, AIPS-JB-0113, AIPS-PI-0001 | Blog post: attackers often write 'you are now DAN' to try to override… |
| b011 | fiction | review | 0.000 | AIPS-IO-0028 | 'You can't ignore the evidence any longer,' said the detective. 'The … |
| b023 | general | review | 0.483 | AIPS-IH-0001 | From now on, the variable should store the updated count rather than … |
| c008 | fiction | review | 0.000 | AIPS-IO-0027 | 雨停之后，她忘记了刚才的争吵，两个人沿着河边慢慢走回家，谁也没有再提起之前发生的事情。 |
| e069 | rag | review | 0.328 | AIPS-SP-0017 | A system prompt is text given to a language model at the start of a c… |
| z030 | business | review | 0.000 | AIPS-IO-0027 | 放弃之前的方案吧，新的设计更简洁，也更容易维护。 |
| z039 | general | review | 0.000 | AIPS-IO-0027 | 请直接给出结论，不需要展开解释过程。 |
| z040 | general | review | 0.000 | AIPS-IO-0027 | 只回复“收到”就可以了，不用写别的内容。 |
| z041 | translation | review | 0.000 | AIPS-IO-0026, AIPS-IO-0027, AIPS-RS-0028 | 不要翻译专有名词，保持原文即可。 |

按类别（被标记 / 总数）：business 1/26，code 0/5，education 0/2，fiction 2/13，general 3/50，hard_negative 0/39，logs 0/3，mixed 0/15，quoted_attack 3/3，rag 1/7，roleplay 0/14，security_discussion 0/9，security_research 0/4，technical 0/19，tool 0/3，translation 1/9

## 2. 上游数据集的 800 条正常翻译句（`trans-prompt-injection-detector`，MIT）

- 带 `context.task=translation`：800 条中非 `allow` 的 **0**（0.0%）。
- 不带上下文：800 条中非 `allow` 的 **0**（0.0%）。

## 3. 已知局限（误报来源）

- 引述攻击字符串的安全讨论、论文、培训材料会触发关键词规则；这是**正则规则的固有限制**，默认策略为 alert-only（`allow/alert/review`），不直接拦截。
- 上游规则以英文为主；中文规则只有 9 条手工规则和少量上游中文/混合规则，覆盖和误报都**缺少真实流量验证**。
- Python `re` 与 Hyperscan/PCRE2 在 Unicode 词边界、大小写折叠上存在差异，C++ 引擎的结果需在 Linux 上用 `tests/corpus/expected/*.expected.jsonl` 做差分确认。
