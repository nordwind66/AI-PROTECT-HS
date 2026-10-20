# 规则源清点 / Source inventory

> 本文件由 `python tools/rules.py inventory` 从 SQLite (`data/ai_prompt_rules.db`) 生成，**请勿手工修改**。生成时间 2026-10-20T02:55:23Z。

数字的含义不同，不能混为一个数：**源规则数 ≠ 分组数 ≠ 条件/Regex 模式数 ≠ 纳入数**。

- **source_rules**: rule definitions found in the locked upstream commit (ATR: one YAML file; trans: one detector group; fevzi: one rule entry)
- **groups**: upstream grouping unit (ATR: category directory; trans: detector group; fevzi: category)
- **conditions_patterns**: regex patterns/conditions inside the source rules (one condition = one pattern)
- **included**: source rules that produced a unified rule (included = all patterns converted, partial = some dropped / pruned)
- **native / prefilter / unsupported**: fate of every source pattern: Hyperscan-native, Hyperscan prefilter + PCRE2 verification, or not convertible; excluded_* patterns never reach the engine

## 总览

| 来源 | commit | 许可证 | 源规则数 | 分组数 | 条件/模式数 | 纳入(含部分) | 排除/不支持 | 原生 Hyperscan | 需 PCRE2 复核 | 不支持 |
|---|---|---|---|---|---|---|---|---|---|---|
| atr | `7c6f9ca48c` | MIT | 836 | 10 | 3459 | 316 | 520 | 1332 | 15 | 131 |
| fevzi_pidr | `81d00cd290` | Apache-2.0 | 20 | 6 | 20 | 16 | 4 | 15 | 1 | 0 |
| trans_pid | `93b913a354` | MIT | 11 | 11 | 135 | 11 | 0 | 135 | 0 | 0 |
| **合计** | | | 867 | 27 | 3614 | 343 | 524 | 1482 | 16 | 131 |

`原生 Hyperscan / 需 PCRE2 / 不支持` 统计的是**源模式**（逐条正则）的最终去向；被语言/范围排除的模式（`excluded_language` / `excluded_scope`）不进入引擎，见下表。

## atr — Agent Threat Rules (ATR)

- 仓库: https://github.com/Agent-Threat-Rule/agent-threat-rules  
- commit: `7c6f9ca48c8a4331658a563c86316207056d77f6` (2026-10-15T18:03:50-04:00)，许可证 MIT，提取器 atr v3
- 上游自述（仅作背景）: README badge states 836 rules；**以锁定 commit 的真实解析结果为准**
- 源规则 836，分组 10，条件/模式 3459
- 规则决定: {'excluded_scope': 500, 'included': 304, 'partial': 12, 'unsupported': 20}
- 模式去向: {'excluded_language': 76, 'excluded_scope': 1905, 'hs_native': 1332, 'hs_prefilter_pcre2': 15, 'unsupported': 131}
- 生成统一规则 316 条，去重后的标准模式 1317 个 （类别 {'hs_native': 1302, 'hs_prefilter_pcre2': 15}）
- 主要排除原因:
    - 415 × excluded_scope: out_of_scope_dir
    - 22 × excluded_scope: technical_exploit
    - 20 × unsupported: detection.method=semantic (embedding / LLM judge) cannot be expressed 
    - 18 × excluded_scope: benchmark_specific
    - 17 × excluded_scope: harm_content
    - 7 × excluded_scope: session_or_multi_agent
    - 6 × excluded_scope: meta_detection_evasion
    - 6 × excluded_scope: needs agent trace / behavioural metrics, not text
    - 4 × excluded_scope: noise_gibberish
    - 2 × excluded_scope: non_prompt_domain
    - 2 × excluded_scope: model_extraction
    - 1 × excluded_scope: multimodal

## fevzi_pidr — prompt-injection-detection-rules

- 仓库: https://github.com/fevziegeyurtsevenler/prompt-injection-detection-rules  
- commit: `81d00cd290fbba37b41b02ad9b5a22ad7af0f829` (2026-08-03T16:14:06+03:00)，许可证 Apache-2.0，提取器 fevzi_pidr v1
- 源规则 20，分组 6，条件/模式 20
- 规则决定: {'excluded_language': 4, 'included': 15, 'partial': 1}
- 模式去向: {'excluded_language': 4, 'hs_native': 15, 'hs_prefilter_pcre2': 1}
- 生成统一规则 16 条，去重后的标准模式 17 个 （类别 {'hs_native': 16, 'hs_prefilter_pcre2': 1}）
- 主要排除原因:
    - 4 × excluded_language: rule language is tr; target languages are en, zh

## trans_pid — trans-prompt-injection-detector

- 仓库: https://github.com/Sirius1906/trans-prompt-injection-detector  
- commit: `93b913a354c8f2597db3e5e9f8af869ee2189423` (2026-05-20T14:41:09+08:00)，许可证 MIT，提取器 trans_pid v2
- 上游自述（仅作背景）: README.md of the repository states '11 categories, 113 regex patterns'；**以锁定 commit 的真实解析结果为准**
- 源规则 11，分组 11，条件/模式 135
- 规则决定: {'included': 11}
- 模式去向: {'hs_native': 135}
- 生成统一规则 11 条，去重后的标准模式 135 个 （类别 {'hs_native': 135}）

## 数据库汇总

- unified_rules: 537
- unified_rules_by_origin: {'imported': 343, 'manual': 194}
- unified_rules_by_status: {'deprecated': 2, 'disabled': 2, 'enabled': 533}
- distinct_patterns: 2153
- patterns_by_class: {'hs_native': 2137, 'hs_prefilter_pcre2': 16}
- patterns_by_profile: {'deobf_v1': 2018, 'trans_v1': 135}
- source_patterns_deduplicated_into_shared_patterns: 30
- tests: 5502
- rules_by_category: {'jailbreak': 168, 'obfuscated_injection': 60, 'prompt_injection': 60, 'instruction_hijacking': 51, 'instruction_override': 51, 'role_spoofing': 44, 'safety_bypass': 43, 'system_prompt_extraction': 35, 'data_exfiltration_instruction': 25}
- rules_by_lang: {'any': 6, 'en': 342, 'mixed': 125, 'zh': 64}
