# 第三方许可与署名 / Third-party notices

本项目的规则库 `data/ai_prompt_rules.db`、发布快照以及随仓库提供的测试样例，**派生自**下列三个开源项目（固定到精确 commit，见 `third_party/sources.lock.json`）。
许可证全文随仓库提供在本目录；上游源码的干净快照在 `third_party/sources/`（逐文件 SHA-256 已锁定）。

| 来源 ID | 项目 | 固定 commit | 许可证 | 版权声明 |
|---|---|---|---|---|
| `atr` | **Agent Threat Rules (ATR)** — <https://github.com/Agent-Threat-Rule/agent-threat-rules> | `7c6f9ca48c8a4331658a563c86316207056d77f6`（2026-10-15） | MIT — [`agent-threat-rules.MIT.LICENSE.txt`](agent-threat-rules.MIT.LICENSE.txt) | Copyright (c) 2026 ATR Contributors |
| `trans_pid` | **trans-prompt-injection-detector** — <https://github.com/Sirius1906/trans-prompt-injection-detector> | `93b913a354c8f2597db3e5e9f8af869ee2189423`（2026-05-20） | MIT — [`trans-prompt-injection-detector.MIT.LICENSE.txt`](trans-prompt-injection-detector.MIT.LICENSE.txt) | Copyright (c) 2026 Sirius1906 |
| `fevzi_pidr` | **prompt-injection-detection-rules** — <https://github.com/fevziegeyurtsevenler/prompt-injection-detection-rules> | `81d00cd290fbba37b41b02ad9b5a22ad7af0f829`（2026-08-03） | Apache-2.0 — [`prompt-injection-detection-rules.Apache-2.0.LICENSE.txt`](prompt-injection-detection-rules.Apache-2.0.LICENSE.txt) | 见该项目的 LICENSE / CITATION.cff |

## 我们如何使用这些项目（以及对它们做了什么修改）

- **提取与转换**：规则被读取（ATR 的 YAML 用本项目自带的安全解析器；两个 Python 来源用 `ast` 读取字面量，**不执行任何上游代码**），其正则被**转换**为统一的规范形式（方言归一、Unicode 空白/换行语义还原、lookbehind 展开、按语言裁剪外语分支、分类为 Hyperscan 原生/预过滤），条件结构、字段约束、测试样例被保留并写入 SQLite。转换的逐条说明保存在 `source_patterns.transform_notes` 与 `source_patterns.fate_reason`；每一条上游规则（包括被排除/不支持的）都在 `source_rules`，并带 `decision_reason`。
- **本地质量决定**：少数过宽的 ATR 条件被排除（`tools/sources/atr_policy.py` 的 `PATTERN_EXCLUSIONS`，原因以 `local_quality:` 开头记录）；另有 1 个 ATR 条件因 Hyperscan 与 PCRE2 都编译不了而被排除（`ENGINE_LIMIT_EXCLUSIONS`，原因以 `engine_limit:` 开头）；trans 检测器三个“通用”组的置信度被调低。这些是**对派生数据的修改**，不是对上游仓库的修改。
- **映射**：上游的严重度/置信度被映射为本项目的 `weight` / `confidence`（映射规则在 importer 源码里，可审计）。
- **版权与署名**：每条导入的规则在 `rule_provenance` 中带有来源仓库、文件路径、commit；发布快照与 `reports/source_inventory.*`、`reports/rule_inventory.csv` 保留这些信息。再分发规则库或快照时，请同时分发本文件与本目录下的三份许可证文本。
- **Apache-2.0（`fevzi_pidr`）**：随仓库保留许可证文本；派生规则（`origin=imported`，provenance 指向该来源）经过上述转换而**被修改**，这里作为醒目声明：*来自 `prompt-injection-detection-rules` 的规则已被转换/裁剪，不再与原始文件逐字相同*。该项目的 LICENSE / CITATION.cff 在 `third_party/sources/prompt-injection-detection-rules/` 中原样保留。
- **MIT（`atr`、`trans_pid`）**：随仓库保留版权声明与许可声明；`third_party/sources/<项目>/LICENSE` 中的原件未被改动。
- **上游测试数据**：`translation_pia_dataset_shuffled.jsonl`（trans 项目，MIT）**没有被复制**，评估脚本直接读取 `third_party/sources/trans-prompt-injection-detector/` 下的原文件。

## 本项目自写的内容

`engine/`、`cli/`、`tools/`、`sql/`、`schemas/`、`scripts/`、`examples/`、`tests/`、`docs/`、`data/manual_rules/`（13 条手工中英文规则）以及 `tests/corpus/*.jsonl`（人工编写的语料）是本项目自己的作品。**本项目自身的许可证尚未选定**——分发之前，请由项目负责人决定并在仓库根目录添加 `LICENSE`；在此之前保留所有权利。手工规则 `origin=manual` 的措辞是原创，但其思路参考了常见的提示词注入分类，不构成对任何上游文本的复制。

## 运行时依赖（均不随本仓库分发）

Hyperscan（BSD-3-Clause，Intel）、PCRE2（BSD-3-Clause 带 PCRE2 例外）、SQLite（公有领域）。它们由使用者自行安装；分发包含它们的二进制时请遵守各自的许可证。

## 外部检索来源

`docs/windows-build.md` 中关于 Hyperscan 在 Windows 上的信息来自网络检索摘要，来源链接列在该文件末尾。
