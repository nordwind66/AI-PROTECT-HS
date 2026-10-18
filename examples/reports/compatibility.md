# 兼容性说明 / Compatibility

> 范围：平台、编译器、依赖版本、产物（`.hsdb`）可移植性、两个平台的结果一致性、正则语义差异。
> 状态约定：**已验证**＝在开发机上实际运行得到的事实；**设计**＝代码与文档的预期，尚未运行；**待实测**＝需要 Linux/Windows 环境。

## 1. 平台支持

| 平台 | 状态 | 说明 |
|---|---|---|
| Linux x86-64（glibc） | **主平台，待 Linux 实测** | GCC ≥ 8（GCC 8 需 `stdc++fs`，CMake 已处理）、Clang；`libai_prompt_guard.so`（SONAME `.so.1`，只导出 `apg_*`） |
| Windows x64（MSVC 2019/2022） | **Windows 未编译验证** | DLL + 导入库 + 静态库；Hyperscan 获取方式风险高（`docs/windows-build.md`）；`pcre2_fallback` 保底 |
| ARM64 / 32 位 / macOS | **不支持（本版）** | `engine/core/platform.h` 将其标为 `other`；manifest 的 `target.arch` 只接受 `x86_64`；Hyperscan 本身不支持 ARM（Vectorscan 另当别论，未评估） |

## 2. 依赖版本

| 依赖 | 最低要求 | 用于 | 备注 |
|---|---|---|---|
| CMake | 3.16 | 构建 | 预设文件 `CMakePresets.json` 需要 3.21 |
| C++ 标准库 | C++17（`<filesystem>`、`std::shared_ptr`、`thread_local`） | 引擎 | **不能**用 C++20 构建：`std::filesystem::path::u8string()` 在 C++20 返回 `char8_t` 串 |
| Hyperscan | 5.x（需要 `HS_FLAG_UCP`、`hs_populate_platform`） | 主引擎 | 运行时的 Hyperscan 版本必须与编译 `.hsdb` 时**完全相同**（manifest 校验） |
| PCRE2（8 位） | 10.30（`pcre2_set_heap_limit`、`pcre2_set_depth_limit`） | 预过滤复核 / 保底后端 | 编译器会检查 PCRE2 能否编译所有预过滤模式；`pcre2_fallback` 产物还要求 PCRE2 编译出**同一组**模式 |
| SQLite | 3.24（schema）；C++ CLI 只读访问 | 规则库 / 编译器 | Python 的 `sqlite3` 模块即可管理；运行时库不依赖 SQLite |
| Python | 3.8+（**设计**）；只在 3.14.7 上运行过 | 规则工具链、测试 | 所有 48 个 `.py` 按 3.8 语法解析通过（`ast.parse(feature_version=(3,8))`），未用已知的 3.9+ API；其他 Python 版本**未测**；只用标准库 |

开发机实际环境（用于解释“已验证”的含义）：Windows 10 Pro 19045，Python 3.14.7（SQLite 由 Python 自带），Unicode 数据库 16.0.0。**没有**安装过任何编译器/库，**没有**在该机器上编译或运行任何 C/C++ 代码。

## 3. 编译产物（`.hsdb`）的可移植性

| 维度 | 是否可跨越 | 机制 |
|---|---|---|
| 操作系统（Linux ↔ Windows） | ❌ | manifest `target.os` 不符 → `APG_ERR_PLATFORM`；`dist/<os>/<arch>/` 分目录 |
| Hyperscan 版本 | ❌（要求**完全相同**的版本字符串） | `hs_deserialize_database` 的版本错误 + manifest 的 `hyperscan_version` 比较 → `APG_ERR_VERSION` |
| CPU 微架构 | 部分 | `--cpu-target generic` 以最保守的 tune/特性构建（可移植性高、速度可能低）；`host` 针对本机；manifest 记录 `cpu_features` 掩码，加载时要求运行机 CPU 提供全部特性；缺失 → `APG_ERR_PLATFORM`。Hyperscan 基线需要 SSSE3 |
| 同一台机器上的重编译 | ✅ | `ai-prompt-guard compile` 对同一快照确定性生成（哈希可比较；**待实测**） |
| 规则快照（`ruleset.meta.json`） | ✅ 跨平台字节一致 | 规范 JSON，SHA-256 固定；两个平台共享同一份 SQLite 规则内容 |
| `pcre2_fallback` 产物 | 取决于 PCRE2 | 没有预编译数据库；加载时 PCRE2 编译同一组模式，失败集合必须与清单一致 |

**正确的发布方式**：规则内容跨平台共享（SQLite + 快照），数据库在每个目标环境**用同一份已发布快照重新编译**。不要拷贝 `.hsdb`。

## 4. 两个平台的结果一致性（设计，待双平台实测）

- 业务字段一致的前提：同一份快照、同一后端类型、同样的归一化表（`tables_version=1`，随源码提交，不依赖运行时 ICU/locale）。`decision / score / matched_rules / needs_context / risk_level` 应当逐位一致；`duration_us`、`engine_version` 的构建元数据、`backend`（hyperscan vs pcre2_fallback）按定义可以不同。
- 数字的格式化不依赖 C 区域设置（自写的 JSON 写入器），文本一律 UTF-8，路径内部一律 UTF-8（`std::filesystem::u8path`）。
- 检测结果是否与 **Python 参考引擎**一致，由 `tests/e2e` 的差分步骤逐样本检查（预期文件 `tests/corpus/expected/*.expected.jsonl` 已生成）。

## 5. 正则语义差异（已知的、需要差分确认的地方）

| 引擎 | 特征 | 与参考引擎（Python `re`，`re.ASCII`）的潜在差异 | 处理 |
|---|---|---|---|
| Python `re`（参考引擎/oracle） | `\w`/`\b`/`\s` 为 ASCII；`re.IGNORECASE` 只折叠 ASCII | 基准 | 转换器把 ES 的 Unicode 空白显式展开为字符类，使 `\s` 与 ES 一致 |
| Hyperscan（`HS_FLAG_UTF8`，不带 UCP 除非规则要求 `u`） | 单遍多模式；无后向引用/环视；`SINGLEMATCH` 每模式只报一次 | Unicode 大小写折叠比 Python 更广（极少数字符）；`.`/锚点/多行语义已在转换阶段显式化 | 不能精确表达的结构（环视、反向引用、原子组…）归 `hs_prefilter_pcre2`，由 PCRE2 复核 |
| PCRE2（UTF 模式，可选 JIT） | 回溯引擎，带 match/depth/heap 限额 | 与 Python 的差异主要在 lookbehind 的长度限制（PCRE2 < 10.43 要求各分支定长）与 Unicode 属性 | 转换阶段把 lookbehind 展开为定长分支；无法展开的归 `unsupported`；2 个展开后的模式 Python `re` 无法编译（参考引擎视为不命中） |
| 归一化 | `fold_v1`：每个码点独立 NFKC（不是整串 NFKC，不做重排） | 与 ATR 的 TypeScript 实现在“组合序列”上可能不同（TS 对整串 `normalize('NFKC')`） | 取舍已在 `normalize_ref.py` 中固定为规范；组合字符序列（如 e + 组合重音）不会被合成 |

## 6. 输入/输出约定

- 输入文本：UTF-8，显式字节长度；`U+0000` 合法；BOM（`U+FEFF`）在 `fold_v1` 视图中被视为可忽略字符（原文视图保留）。非法 UTF-8 → 结构化错误结果，不崩溃。
- 输出：UTF-8 JSON，`NUL` 结尾；结果不含原始文本，只有偏移。
- 文件：LF 行尾（`.gitattributes` 固定）；规则库为单文件 `journal_mode=delete`。

## 7. 上游兼容

- ATR：按锁定 commit（`7c6f9ca…`）的 `rules/**/*.yaml` 解析，字段解析/测试语义对照其参考测试器；上游 schema 变化时 `miniyaml` 遇到不认识的语法**报错**而不是跳过，importer 对未知字段/操作符给出 `unsupported` 并记录。
- trans / fevzi：用 `ast` 读取字面量；预处理函数的 AST 哈希被固定（`EXPECTED_PREPROCESS_AST_SHA256`），上游改了预处理逻辑会让导入失败而不是静默产生不同的 `trans_v1`。
