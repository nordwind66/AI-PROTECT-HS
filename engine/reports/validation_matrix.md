# 验证矩阵 / Validation matrix

**状态只有六种，不混用：**

| 状态 | 含义 |
|---|---|
| ✅ 已实测通过（开发机） | 在开发机（Windows 10，Python 3.14.7，仅标准库）上**实际运行**并看到结果。范围：只覆盖 Python 工具链 / 数据 / 参考引擎，**不包含任何 C++** |
| ✅ Linux 实测 | 在使用者的 Linux 机器上实际运行并看到输出，输出原文保存在 `reports/logs/`（见 §12）。有两种来源：使用者自己运行并贴回（§12.1–12.2），以及使用者授权后开发会话经 SSH 在同一台机器上运行（§12.3） |
| ❌ 实测失败 | 实际运行后失败，附原因与处理 |
| 🚫 环境限制未测 | 在当前环境**无法**执行（没有编译器、没有真实流量……）且任务书不允许改变环境 |
| ⏳ 待 Linux 执行 | 代码/脚本/预期结果已备好，必须在独立 Linux 环境运行；**没有日志不得改成通过** |
| ⏳ 待 Windows 执行 | 同上，Windows 环境 |

> 没有性能基准（没有延迟、吞吐、内存数据）；§12 里的耗时只是单次运行的观察值，不是基准。`Python 参考引擎` 的结果只说明“转换与规则语义自洽”，**不是** Hyperscan/PCRE2 引擎的结果；C++ 引擎与它的一致程度见 §12 的差分记录。

## 0. 在开发机上实际执行过的命令

| 命令 | 结果 |
|---|---|
| `python tools/build_rules_db.py --fresh` | 退出码 0，≈34 s；输出 `reports/build_rules_db.log` |
| 同一命令在另一个路径再执行一次，比较 `export-snapshot` 的 SHA-256 | 完全相同（快照 `34e6d9af…527a7a`）→ 内容可复现 |
| `python tools/rules.py --db <交付库的副本> import --source all`（第二次导入） | 867 条源规则全部 `unchanged`，行数不变 → 幂等 |
| `python -X utf8 -m unittest discover -s tests/python` | 见 §11（运行结果记录） |
| `python tools/static_checks.py` | 50 个 C/C++ 文件无问题（**不是编译**） |
| `python tests/e2e/run_e2e.py --cli "python tests/e2e/fake_cli.py" --backend pcre2_fallback …` | 全部 PASS — **仅证明端到端脚本自身可用**（对象是 Python 替身，不是 C++） |
| `python tools/rules.py eval --report --write-expected` | 生成 `tests/corpus/expected/*.expected.jsonl`、`reports/false_positive.md`、`reports/detection_eval.md` |

**开发机上从未执行过**：任何 C/C++ 编译、`ctest`、`ai-prompt-guard`、DLL/SO 加载、Hyperscan 或 PCRE2 调用、性能测试（开发机没有编译器，任务书不允许安装）。C++ 的实测结果全部来自使用者的 Linux 机器（§12）。

## 1. 规则源完整性（任务书 10.2-1）

| 项 | 状态 | 证据 |
|---|---|---|
| 三个仓库固定 commit、许可证、逐文件 SHA-256 | ✅ | `rules.py sources verify`；`tests/python/test_importers.py::test_locked_sources_match_the_lock_file`；Linux：`init_rules.sh` 步骤 1 “third_party/sources matches sources.lock.json” |
| 逐条追踪：每条上游规则（867）与每条上游正则（3 614）都有去向与原因 | ✅ | `test_deliverables.py::test_every_source_rule_and_pattern_is_accounted_for`；`reports/source_rules.csv`、`reports/source_inventory.md` |
| 同一来源导入两次不重复 | ✅ | 全量第二次导入全部 `unchanged`（`test_importers.py::FullImportIdempotenceTests`） |
| 上游变更产生 diff 与新修订、本地改动不被覆盖（`merge_conflict` 警告） | ✅ 变更检测 / 🚫 真实上游新 commit 未测 | `test_a_changed_upstream_definition_creates_a_new_revision_of_the_same_rule`（用修改 importer 策略模拟上游变化）；没有拉取过比锁定版本更新的 commit |
| 排除 / unsupported 都有记录 | ✅ | `source_rules.decision_reason` 非空（测试断言）；`reports/language_review.md`；引擎限制排除（`engine_limit:`）见 `PROGRESS.md` §10 |

## 2. SQLite（10.2-2）

| 项 | 状态 | 证据 |
|---|---|---|
| migration 建表、重复执行、校验和防篡改 | ✅ | `test_database.py::SchemaTests`；Linux：`db check` 通过（§12） |
| 外键、唯一键、CHECK 约束 | ✅ | `test_database.py::ImmutabilityTests::test_foreign_keys_are_enforced`；`PRAGMA foreign_key_check` |
| 事务回滚 | ✅ | `add --dry-run` / `update --dry-run` 在事务内执行后回滚（`test_dry_run_changes_nothing`）；导入在单事务内 |
| 发布不可变（成员/模式/快照/版本被冻结） | ✅ | `test_database.py::test_a_published_version_is_frozen` 等 |
| 版本回滚（只移动指针 + 审计） | ✅ ；Linux：✅ | `test_rule_lifecycle.py::test_activate_and_rollback_move_the_pointer_and_leave_an_audit_trail`；Linux e2e `release flow` PASS（§12） |
| 备份 / 恢复 / 交付快照（`journal_mode=delete`） | ✅ | `test_database.py::BackupTests` |
| 审计哈希链 | ✅ | `AuditChainTests`（篡改被发现）；Linux：`db check` 的 “audit chain ok” |
| WAL 快照一致性、并发读与管理写入解耦 | 🚫 | 设计上运行时不访问 SQLite；`db snapshot` 经在线备份 API 保证一致；**没有做并发压力测试** |

## 3. 规则语义（10.2-3）

| 项 | 状态 | 证据 / 范围 |
|---|---|---|
| ATR `any/all/NOT`、字段限制 | ✅（Python 参考引擎）· Linux：✅（差分） | `test_refengine.py`；上游 3 504 个测试样例复算一致、0 不一致（`verify-tests`）；C++ 引擎在 Linux 上与参考引擎的差分见 §12 |
| 翻译规则分组权重（`score_group` 不叠加）、上下文门控 | ✅（Python）· Linux：✅（e2e `CLI contract` 的上下文用例 PASS） | `test_refengine.py`、`test_rule_lifecycle.py::test_rules_with_identical_evidence_do_not_stack` |
| 英文 flags（ATR 强制 `i`）、方言转换（ES `.`/`\s`/`$`、Python `\Z`） | ✅（Python 转换器 + 参考引擎） | `test_convert.py` |
| 与原项目测试样本差分 | ✅（Python 参考引擎对上游样例）· C++ 引擎：见 §12 差分 | 一致 3 504；不一致 0；`skipped_scope` 46（部分转换规则）；不可复算 0（旧版有 11 个，因为 2 个含变长 lookbehind 的模式 Python `re` 编不了；参考引擎已补，见 `PROGRESS.md` §10）；已知缺口样例 309 条不作为断言 |

## 4. 中文、英文与混合（10.2-4）

| 项 | 状态 | 证据 |
|---|---|---|
| 九类攻击的中英文代表样例 | ✅（Python 参考引擎，人工语料 72 条：应检出 66、已知缺口 6）· Linux：C++ 与参考引擎逐条一致（72/72，0 差异） | `reports/detection_eval.md`；`tests/corpus/attacks_zh_en.jsonl`；§12 |
| 绕过变体：零宽字符、全角、西里尔同形字、RLO、英文字符间空格、Base64 指令、leetspeak、繁体 | ✅（Python）：全部被检出（后四项依赖上游 ATR 的对应规则，而不是归一化）；**仍漏检**：中文字符间空格、纯改写（中英）、无注入标记的社会工程；法语只得 `review` | `reports/detection_eval.md` 的“已知缺口样本的实际结果” |
| 混合语言 | ✅（Python） | `x001–x005` |
| “不能因为用例里写了词语就自动判为攻击”：已知缺口不作为通过断言 | ✅ | `known_gap` 种类不参与断言 |

## 5. 正常文本误报（10.2-5）

| 项 | 状态 | 证据 |
|---|---|---|
| 技术文章、合法角色扮演、小说对白、代码、日志、翻译文本、引述攻击字符串、正常中英混用、安全研究讨论 | ✅（Python，221 条人工语料 + 上游数据集 800 条正常翻译句）· Linux：C++ 与参考引擎对 221 条人工正常语料逐条一致（0 差异） | `reports/false_positive.md`；引述攻击字符串的 3 条样例**预期**被触发（正则的固有限制，已记录） |
| 真实业务流量的误报评估 | 🚫 | 没有脱敏的真实流量；这是使用方必须完成的工作 |

## 6. C ABI（10.2-6）

| 项 | 状态 |
|---|---|
| C 调用 / C++ 调用 / `dlopen` / `LoadLibrary` / Python / Go / Rust 示例 | ✅ Linux：e2e “example programs” 在 Hyperscan 与 PCRE2 两个后端上都 PASS（C、C++、dlopen、Python/ctypes 示例都返回了检测结果；用系统 Python 3.12）。使用者那次用 conda 的 Python 3.13 时 Python/ctypes 示例加载失败：conda 自带较旧的 libstdc++（`GLIBCXX_3.4.30 not found`），是**环境冲突**，不是库的缺陷，harness 现在遇到这种错误会用系统 libstdc++ 的 `LD_PRELOAD` 重试（该重试路径本身还没有在 conda 环境里被验证过）。Windows 示例 ⏳ 待 Windows；Go/Rust 未纳入自动测试 |
| 错误码、出参置空、`apg_last_error`、缓冲区释放、重复创建销毁 | ✅ Linux（`ctest` 的 `cpp_unit` 通过，0.50 s；包含 `tests/cpp/test_engine.cpp` 的 C ABI 用例；pcre2_fallback 后端） |
| 跨线程扫描、**热更新期间在途请求安全** | ✅ Linux（同一个 `cpp_unit`：`concurrent_scans_during_hot_reload`）· ✅ ASan/UBSan 与 TSan 下的 24 项单测均无报告（§12.3） |

## 7. 兼容性（10.2-7）

| 项 | 状态 |
|---|---|
| 两平台 JSON 业务字段一致 | ⏳ 待 Linux + Windows（需要同一快照、同一后端类型） |
| UTF-8 / 中文多字节 / 超大文本 / 错误输入 | ✅ Linux（e2e `CLI contract, context, invalid UTF-8` PASS；`malformed requests are refused` PASS）· 超大文本 / 限额的专门用例仍是剩余工作 |
| 缺失上下文 | ✅（Python 参考引擎）· ✅ Linux（e2e `CLI contract` 的 `--context` 用例；`context_gating_reports_needs_context` 在 `cpp_unit`） |
| PCRE2 复核 | ✅ Linux（502 个预过滤模式经 PCRE2 复核；差分 1 293 条中 1 276 条完全一致，其余 17 条是参考引擎缺口，见 §12） |
| Hyperscan 版本 / CPU 不匹配被拒绝 | ⏳ 待 Linux（需要两个环境或人为改写 manifest；加载逻辑已写，`verify` 在本机通过） |

## 8. 可靠性（10.2-8）

| 项 | 状态 | 说明 |
|---|---|---|
| 坏 SQLite（损坏文件、篡改审计链、篡改 migration） | ✅ | `test_database.py`；`db restore` 拒绝非数据库来源 |
| 坏 `.hsdb`、manifest 与文件不一致、`build_hash` 被改 | ✅ Linux | e2e `tampered artifacts are rejected` PASS（0.1 s） |
| 编译失败的隔离与报告 | ✅ Linux | 真实触发：模式 11128（旧快照）被 Hyperscan（“Pattern is too large”）和 PCRE2（“regular expression is too large”）同时拒绝，被隔离并写入报告（错误原文、规则、溯源），其余 1 500 个模式照常编译；`manifest.status = partial` |
| 并行逐条筛选、分片并行编译、超时放弃、放宽大计数重复 | ✅ Linux（一次运行，16 线程） | `init_rules.sh`：83.4 s 完成，无崩溃；2 次尝试达到 30 s 时限被放弃并成功改用放宽形式；“`hs_compile*` 可被多线程并发调用”只是**未被证伪的假设**（一次无崩溃的运行不是证明） |
| 一个 profile 的多个 `.hsdb` 分片的加载与扫描 | ✅ Linux | 19 个数据库（fold_v1 16 个 + trans_v1 3 个）加载与 `verify` 通过；16 个分片与 3 个分片（`--shards 3`）的差分结果完全相同（同样的 17 条差异） |
| schema migration 失败 | ✅ | 校验和不符时拒绝；单事务执行 |
| 内存不足模拟 | 🚫 | 未实现（剩余工作） |
| 超限（max_text / max_hits / PCRE2 限额 / 预算） | ⏳ 待 Linux | `invalid_utf8_and_limits_are_structured_results` 覆盖文本与请求大小（`cpp_unit` 通过）；`max_hits`/PCRE2 限额没有专门测试用例（剩余工作） |
| 热更新失败回滚 | ✅ Linux | `reload_switches_atomically_and_failed_reload_keeps_old_rules` 在 `cpp_unit` 中通过 |
| race / fuzz | ✅ Linux：TSan 下 24 项单测（含线程池与热更新期间并发扫描）0 条警告 · 🚫 模糊测试未提供（剩余工作）· 注意 TSan 看不到未插桩的 libhs 内部 |

## 9. 性能（10.2-9）

**没有基准。**本仓库**没有任何延迟、吞吐、内存基准**。计划与脚本：`reports/performance.md`、`scripts/linux/bench.sh`（必须显式 `--run`）。可引用的事实（不是基准）：SQLite 库文件 ≈ 13.9 MB，发布快照 1 679 307 字节；使用者那次 16 线程编译的单次观察值见 §12。

## 10. 其他检查

| 项 | 状态 | 证据 |
|---|---|---|
| C/C++ 源码的静态一致性（括号、include、CMake 清单、公共 API、JSON 契约） | ✅（**不是编译**） | `tools/static_checks.py`；`test_deliverables.py::test_static_checks_pass` |
| JSON Schema 与真实文档（快照、规则规格、指针） | ✅ | `test_schemas.py` |
| manifest / build_report / info / 响应 的 Schema 对 C++ 实际输出 | ✅ Linux | e2e `compile`、`load, verify, info`、`differential` 对每个响应做 Schema 校验（已跑到，除下面“失败项”外无 Schema 报错） |
| 端到端脚本自身 | ✅（对 Python 替身） | `test_e2e_harness.py`（含“说谎的引擎必须被差分步骤抓住”） |
| 交付物一致性（DB 完整性、校验和文件、快照与预期结果同步、语料格式） | ✅ | `test_deliverables.py`（校验和用例在库已被使用后自动跳过，见 §12 的第一条教训） |
| 构建（Linux）、`ctest` | ✅ Linux | `build/linux` 构建成功（GCC 13.3.0 + `-Wall -Wextra`：零警告；曾有 1 个 `-Wcomment`，已修）；`cpp_unit` 通过（25 项） |
| ASan/UBSan、TSan（Linux） | ✅ | §12.3、`reports/logs/linux_sanitizers_2026-10-17.log` |
| 构建（Windows）、CI | ⏳ 待 Windows / ⏳ 待触发 | 见 `build_matrix.md` |

## 11. 运行结果记录（开发机，仅 Python 工具链）

| 项 | 内容 |
|---|---|
| 环境 | Windows 10 Pro 10.0.19045，Python 3.14.7，仅标准库；没有编译器 |
| 命令 | `python -X utf8 -I -m unittest discover -s tests/python` |
| 结果 | `Ran 106 tests in 130.191s — OK`（输出尾部：`static checks: 50 C/C++ files, CMake lists, public API, JSON contract: no problem found (this is NOT a compilation)`） |
| 规则库 | `python -X utf8 tools/build_rules_db.py --fresh`：退出码 0，33.8 s；`db check`：integrity、foreign key、migration、审计链均 ok；数据库文件 SHA-256 见 `data/ai_prompt_rules.db.sha256`（含时间戳，仅作交付指纹） |
| 快照复现 | 另一路径的全新构建：快照 SHA-256 `34e6d9afaa76ca9920d9cac6c9f897e75bfb63bf5063c3dad12deb4117527a7a`，与交付库的快照逐字节相同 |
| 端到端脚本自测 | 对 `tests/e2e/fake_cli.py` 全部 PASS（仅脚本自身；不是 C++ 结果） |

## 12. Linux 实测记录（使用者运行 + 开发会话经 SSH 运行；原文在 `reports/logs/`，**未经编辑**）

环境（来自输出）：x86-64 Linux 7.0.0-31-generic，glibc 2.39，Python 3.13.5（conda `base`），Hyperscan 5.4.2 2024-04-19，16 个 CPU 线程。编译器与 PCRE2 版本没有出现在输出里。

### 12.1 `scripts/linux/init_rules.sh`（日志：`reports/logs/linux_init_rules_2026-10-17.log`）

被测：快照 `692b58da…`（1 501 个模式），并行/分片编译器。

| 观察 | 结果 |
|---|---|
| 总耗时 | 83.4 s（逐条筛选 fold_v1 52.2 s + 分片编译 30.2 s + trans_v1 0.5 s；16 个工作线程）。这是**单次观察值，不是基准**。对比：旧的单线程版本数小时未完成 |
| 产物 | 19 个 `.hsdb`（fold_v1 16 个、trans_v1 3 个），合计约 91 MiB；其中两个分片各只含 1 个模式却各有 3.3 MiB（编译近 30 s 的原生模式） |
| 分类 | 998 原生 + 502 预过滤（486 个由原生降级、480 个放宽了大计数重复）+ 1 个被隔离 = 1 501 |
| 被隔离的模式 | 11128（ATR-2026-01005 的第一个条件，规则 AIPS-IO-0017）：Hyperscan “Pattern is too large”，PCRE2 “regular expression is too large at offset 2243”。`manifest.status = partial` |
| 超时 | 2 次原生尝试达到 30 s 时限被放弃，随后用放宽形式成功；CLI 用 `_Exit` 退出（输出了 “2 compiler thread(s) were abandoned”） |
| 自检与校验 | 编译内的 `self-test`（加载全部 19 个库 + PCRE2 复核器）通过；`register-artifact`、`activate`、`verify` 通过：“OK: manifest, hashes, platform, Hyperscan/PCRE2 versions and databases verified” |

### 12.2 `scripts/linux/test.sh`（日志：`reports/logs/linux_test_sh_2026-10-17.log`）

被测：同一个旧快照 `692b58da…`；Python 参考引擎是修复 lookbehind 之前的版本。

| 套件 | 结果 | 原因与处理 |
|---|---|---|
| C++ 单元测试（`ctest` `cpp_unit`） | ✅ 通过（0.50 s） | — |
| Python 单元测试（101 项） | 99 通过 · ❌ 2 失败 | ① `test_checksum_file_matches`：`init_rules.sh` 直接写了 `data/ai_prompt_rules.db`（登记、激活），文件指纹不再匹配 → 库被使用后该用例跳过，`init_rules.sh` 会提示；② `test_generated_tables_and_vectors_are_up_to_date`：使用者的 Python 3.13（Unicode 15.1）与生成表时的 3.14（Unicode 16.0）数据不同 → 版本不匹配时跳过（提交的表是权威，C++ 使用它们；归一化黄金向量用例在 Linux 上通过） |
| e2e `compile` | ❌ | 1 个被隔离的模式（上表）→ 已在 importer 里按 `engine_limit` 排除（新快照 `34e6d9af…`） |
| e2e `load, verify, info` | ❌ | 同一个原因（断言 `patterns_failed == 0`；断言没有消息，已补） |
| e2e 差分（1 293 个样本） | ❌ 17 条不同 | benign_zh_en 61/61、benign_extended 160/160、attacks_zh_en 72/72 完全一致；trans_dataset 1000 条里 17 条不同，**全部**是 C++ 多命中了 `AIPS-IH-0005`。原因：该规则的 2 个模式含变长 lookbehind，Python `re` 编不了，旧参考引擎当它们不命中；PCRE2 能判断。参考引擎已改为把 `(?<!a|bc)` 拆成 `(?<!a)(?<!bc)`，并重新生成预期；用 Python 替身跑 harness 得到的“got”与 Linux 上 C++ 的 17 条结果逐字相同（分数也相同），证实了这个解释 |
| e2e 确定性、CLI 契约（含 `--context`、非法 UTF-8）、畸形请求、篡改检测 | ✅ PASS | — |
| e2e 分片构建（`--jobs 2 --shards 3`） | ❌（同样的 17 条差异），耗时 351.6 s | 不是死循环：2 个线程、3 个各近 500 个模式的大分片编译很慢，而 harness 吞掉了编译进度，看上去像卡住。16 个分片与 3 个分片的检测结果**完全相同**。步骤已改为：默认构建本来就是多分片时直接检查它；harness 现在实时显示编译进度 |
| e2e 发布流程（新规则 → 发布 → 编译 → 激活 → 检测 → 回滚） | ✅ PASS（183.6 s） | “1.0.0 -> 1.0.1: new rule AIPS-IO-0033 detected, rollback to 1.0.0 removed it again” |
| e2e 示例程序 | ❌ | conda Python 的 libstdc++ 太旧：`GLIBCXX_3.4.30 not found (required by libai_prompt_guard.so)`。环境冲突，harness 现在用系统 libstdc++ 的 `LD_PRELOAD` 重试 |

**§12.1–12.2 的范围**：使用者自己的两次运行，用的是旧快照 `692b58da…`。它们证明：C++ 引擎在 Linux 上能构建、能用 Hyperscan + PCRE2 编译并加载真实规则集、扫描结果与参考引擎在 1 293 个样本中的 1 276 个逐字段一致，其余 17 个已解释。§12.3 在新快照 `34e6d9af…` 上补全了这些结果。

### 12.3 开发会话经 SSH 在同一台 Linux 机器上运行（使用者授权；原文在 `reports/logs/`，**未经编辑**）

环境：Ubuntu 24.04（内核 7.0.0-31，glibc 2.39）、GCC 13.3.0、CMake 3.28.3、Hyperscan 5.4.2-2、PCRE2 10.42、SQLite 3.45.1、系统 Python 3.12.3（另外用 conda 的 Python 3.13.5 跑了 Python 单测）、24 个 CPU 线程、62 GB 内存。

| 步骤 | 结果 | 日志 |
|---|---|---|
| 同步前核对 | 比较 172 个文件的 SHA-256：30 个不同、2 个缺失；发现远端 `examples/CMakeLists.txt` 的内容被换成了根目录的 `CMakeLists.txt`（会使重新配置失败），并且 `examples/` 下有一份被误解压进去的完整项目副本（`examples/engine`、`examples/tests` …，使 `static_checks` 数到 100 个文件而不是 50 个）。已备份被覆盖的 31 个文件到远端 `.sync-backup/`，同步后 172 个文件校验一致；误解压的副本**没有动**，只报告 | — |
| 构建 | 增量构建成功；GCC 13.3 + `-Wall -Wextra`：唯一的警告是公共头文件注释里的 `/*`（`-Wcomment`），已改写，之后零警告 | — |
| `init_rules.sh`（新快照 `34e6d9af…`） | 1 500 个模式，`failed: 0`，`status: ok`，19 个数据库，85.9 s（旧默认时限）；`register-artifact`、`activate`、`verify` 通过 | `linux_init_rules_ssh_after_sync_2026-10-17.log` |
| `test.sh`（第一次） | `cpp_unit` 通过；e2e 11 项全部 PASS，差分 1 293 个样本 0 差异；Python 单测 1 个失败：`test_importing_everything_again_…` —— 导入器对上游 `preprocess_text` 的 AST 哈希依赖 `ast.dump()`，而 `ast.dump()` 在 Python 3.13 改了格式，系统 Python 3.12 上算出的哈希与 3.13/3.14 不同，于是 11 条 trans 规则被判为“已变更” | `linux_test_sh_ssh_after_sync_2026-10-17.log` |
| AST 哈希修复 | `stable_ast_dump`（自己渲染语法树，输出与 3.13+ 的 `ast.dump` 逐字相同）；新增跨版本测试；在 Python 3.12.3、3.13.5（Linux）和 3.14.7（开发机）上都得到同一个哈希，导入器测试全部通过 | — |
| 全部 Python 单测 | Python 3.12.3：107 项 OK（1 项跳过：Unicode 数据版本与生成表的不同）；Python 3.13.5：107 项 OK（1 项跳过） | — |
| 两级编译时限 | 实验 `--pattern-timeout 15`：筛选 27.5 s（原 49 s）、分片 22 s、总 50.4 s、0 个被隔离、5 次尝试达到时限后用放宽形式成功；据此把默认值改为：仍有放宽形式可以兜底的尝试 15 s（`--native-timeout`），最后一次机会 60 s（`--pattern-timeout`） | `linux_compile_pattern_timeout15_2026-10-17.log` |
| `init_rules.sh`（最终代码） | 48.7 s，0 个被隔离，`status: ok`；996 原生 + 504 预过滤（488 个由原生降级、483 个放宽了大计数重复）；`verify` 通过 | `linux_init_rules_final_2026-10-17.log` |
| `test.sh --backend both`（最终代码） | **退出码 0**：`cpp_unit` 通过（25 项）；Python 107 项 OK（1 跳过）；e2e **20/20 PASS**（Hyperscan 与 PCRE2 两个后端各 10 项：编译、加载校验、差分 1 293 个样本 **0 差异**、确定性、CLI 契约、畸形请求、篡改检测、分片、发布流程、示例程序）；总耗时 3 分 51 秒 | `linux_test_sh_final_2026-10-17.log` |
| ASan + UBSan | `build.sh --asan`：24 项单测通过，没有任何 Sanitizer 报告（含 LeakSanitizer，退出码 0） | `linux_sanitizers_2026-10-17.log` |
| ThreadSanitizer | 24 项单测通过，**0 条 ThreadSanitizer 警告**（含线程池的并行/超时放弃/异常用例和 `concurrent_scans_during_hot_reload`）。注意：系统的 libhs 没有被插桩，TSan 看不到 Hyperscan 内部；“`hs_compile*` 可被多线程并发调用”仍是假设，证据是多次并行编译无崩溃且每次分类数量完全相同（998/502、486 降级、480 放宽） | `linux_sanitizers_2026-10-17.log` |

**还没有做的**：性能基准（`bench.sh --run` 须使用者明确要求）、模糊测试、内存不足模拟、`max_hits` / PCRE2 限额的专门用例、Windows、真实流量下的误报评估、`--jobs 1` 与并行构建逐字节对比。
