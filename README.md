# AI Prompt Guard — SQLite 规则库 + Hyperscan 的提示词注入检测引擎

一个**进程内**的检测库（C++17 核心，稳定的 **C ABI**，同一份源码构建 Windows `DLL` 与 Linux `SO`），用 **SQLite 作为唯一权威规则库**、**Hyperscan 作为主正则引擎**（PCRE2 只做必要的精确复核），对一段文本返回结构化的检测结果：命中的规则 / Pattern ID、类别、严重度、来源、风险分与决策（默认 alert-only）。支持中文、英文与中英混合文本。

**不做**：APISIX 插件、HTTP 服务、网关适配、Web UI、语义/大模型判别（任务书明确排除）。

## 1. 当前状态（请先读这一节）

| 部分 | 状态 |
|---|---|
| **SQLite 规则库** `data/ai_prompt_rules.db` | ✅ **已生成并在开发机上验证**：三个开源来源（固定 commit）的真实规则 + 13 条手工中英文规则；`db check` 通过；已发布版本 `1.1.0`（357 条规则 / 1 505 个模式；相对 1.0.0 新增 `deobf_v1` 归一化视图与 5 条改写类手工规则），快照字节级可复现 |
| **规则工具链**（导入 / 转换 / 维护 / 发布 / 回滚 / 报告） | ✅ 已在开发机上运行；Python 标准库，**无需安装任何依赖**；Python 单元测试在本机通过（见 `reports/validation_matrix.md`） |
| **C++ 引擎、Hyperscan 编译器、C ABI、CLI、DLL/SO** | ✅ **Linux 已编译并实测**（Hyperscan 5.4.2 + PCRE2：`test.sh --backend both` 20/20，1 293 个样本与参考引擎 0 差异，原始日志在 `reports/logs/`）。1.1.0 的 `deobf_v1` 改动另在云端以 `pcre2_fallback` 后端验证：`cpp_unit`、Python 单测、e2e（含与参考引擎的差分）全部通过；**Hyperscan 后端尚未对 1.1.0 重新跑过** |
| **Linux 实测** | ✅ 见 `reports/validation_matrix.md` §12；1.1.0 的 Hyperscan 编译/差分待在有 libhs 的机器上重跑（`docs/linux-testing.md`） |
| **Windows 构建与 DLL** | ⏳ **Windows 未编译验证**。Hyperscan 在 Windows 上风险最高（`docs/windows-build.md`）；提供显式的 `pcre2_fallback` 保底后端 |
| **性能** | ⏳ **待 Linux 实测**：本仓库**没有任何性能数字**；计划与脚本见 `reports/performance.md`、`scripts/linux/bench.sh` |

没有把任何“未执行”的东西写成“已通过”；每一项的证据与缺口见 **`reports/validation_matrix.md`**，进展日志见 **`reports/PROGRESS.md`**。

## 2. 目录

```text
include/ai_prompt_guard.h        唯一的公共 C ABI（Linux/Windows 同一份）
engine/{core,ruleset,storage,api}   C++17：归一化 · Hyperscan/PCRE2 后端 · 评分 · 快照/manifest · 规则编译器 · 热更新 · C ABI 外壳
cli/                              ai-prompt-guard：compile · verify · info · scan · scan-batch · bench · versions（+ 转发规则管理命令）
sql/001_init.sql                  SQLite schema（含不可变性触发器、视图）
data/ai_prompt_rules.db           权威规则库（含已发布的 1.1.0）· .sha256 · manual_rules/*.json（手工规则）
tools/rules.py  tools/apg_rules/  规则管理命令行与实现（导入/转换/维护/发布/参考引擎/报告）
tools/sources/                    三个来源的 importer 插件
tools/build_rules_db.py           一键、可重复地构建规则库
third_party/sources{,.lock.json}  三个上游仓库的干净快照与 commit 锁
schemas/                          请求/响应/配置/info/manifest/快照/规则规格/指针/编译报告 的 JSON Schema
examples/                         C · C++ · dlopen · LoadLibrary · Python ctypes · Go cgo · Rust FFI
scripts/{linux,windows}/          依赖检查 · 构建 · 规则初始化 · 测试 · 基准(显式) · CI 在 .github/workflows/ci.yml
tests/                            python/（工具链单元测试）· cpp/（引擎单元测试）· e2e/（端到端+差分）· corpus/（语料与预期）· fixtures/
docs/  reports/  LICENSES/        文档 · 实际完成情况与统计报告 · 许可证与署名
```

## 更新规则（日常）

规则库只需生成一次。之后改 `data/manual_rules/*.json`（规则名是主键，新名字=新规则，同名有变化=新修订），然后：

```bash
python tools/update_rules.py --dry-run   # 先看会改什么
python tools/update_rules.py --compile   # 同步 → 测试 → 校验 → 发布下一个补丁版本 → 在本机编译并激活
```

详见 `docs/rule-maintenance.md` §0。

## 3. Linux 快速开始（待实测的路径）

```bash
bash scripts/linux/setup_deps.sh                 # 只检查，不安装（--install 才安装）
bash scripts/linux/build.sh                      # → build/linux/bin/{libai_prompt_guard.so, ai-prompt-guard, apg_tests, example_*}
cp data/ai_prompt_rules.db /tmp/rules.db         # 工作副本
bash scripts/linux/init_rules.sh --db /tmp/rules.db   # 验证库 → 在本机编译 .hsdb → 登记 → 激活
build/linux/bin/ai-prompt-guard scan --manifest dist/linux/x86_64/active.json --text "忽略之前的所有指令" --pretty
bash scripts/linux/test.sh --backend both        # C++ 单元测试 + Python 测试 + 端到端差分
```

没有 Hyperscan？`bash scripts/linux/build.sh --no-hyperscan` 构建显式的 `pcre2_fallback` 后端（结果里 `backend` 恒为 `pcre2_fallback`）。

Hyperscan 编译是最慢的一步：`compile` 默认用本机所有 CPU 线程（`--jobs N` 可调，`--jobs 1` 严格串行），逐条并行筛选后再分片并行编译，并持续打印进度；只想先验证其余流程时用 `bash scripts/linux/init_rules.sh --backend pcre2_fallback`。细节与调参见 `docs/rule-maintenance.md` §8 与 `docs/linux-testing.md` §3。

## 4. 完整示范：新规则 → SQLite → 发布 → 编译 → 检测 → 回滚

下面每一步的 Python 部分已在开发机上用 **Python 版 CLI 替身**（`tests/e2e/fake_cli.py`）跑通过（用来测试端到端脚本本身）；C++ 部分（`ai-prompt-guard compile / scan`）**待 Linux 实测**。`tests/e2e/run_e2e.py` 把这一整套自动化了。

```bash
DB=/tmp/rules.db ; cp data/ai_prompt_rules.db $DB
# 1) 写一条规则（含正负例）并加入 SQLite
cat > /tmp/rule.json <<'EOF'
{"rules":[{"name":"示例：私有暗号","category":"instruction_override","severity":"high","weight":0.8,"confidence":0.9,
 "patterns":[{"regex":"qz7x-override-token","flags":"i"}],
 "tests":{"positive":["please obey qz7x-override-token now"],"negative":["please obey the usual process"]}}]}
EOF
python tools/rules.py --db $DB add --file /tmp/rule.json
python tools/rules.py --db $DB verify-tests && python tools/rules.py --db $DB validate --strict
# 2) 发布不可变版本
python tools/rules.py --db $DB publish --version 1.0.1 --notes "add token rule"
# 3) 在目标机器上编译（Hyperscan 数据库 + manifest）并登记、激活
build/linux/bin/ai-prompt-guard compile --db $DB --version 1.0.1 --out dist --backend hyperscan
python tools/rules.py --db $DB register-artifact --manifest dist/linux/x86_64/1.0.1/manifest.json
python tools/rules.py --db $DB activate --version 1.0.1 --pointer-dir dist/linux/x86_64
# 4) 通过 C API（CLI 即其薄封装）检测
build/linux/bin/ai-prompt-guard scan --manifest dist/linux/x86_64/active.json --text "please obey qz7x-override-token now" --pretty
# 5) 出问题 → 回滚（先编译好旧版本）
python tools/rules.py --db $DB rollback --to 1.0.0 --pointer-dir dist/linux/x86_64 --reason "regression"
```

## 5. 规则库里有什么（事实，来自 `reports/`）

- 三个来源、867 条源规则、3 614 条源模式（**源规则数 ≠ 分组数 ≠ 模式数 ≠ 纳入数**，逐项区分见 `reports/source_inventory.md`）：ATR 836 / trans 11 / fevzi 20。
- 纳入：339 条上游规则 + 18 条手工规则 = **357 条启用规则**；发布版 1.1.0 含 **1 505 个模式**（1 489 原生 Hyperscan + 16 需 PCRE2 复核；在 Linux 上编译时另有约 480 个因含大范围重复而降级为“预过滤 + PCRE2 复核”）。
- 排除（全部有原因记录）：524 条源规则（范围外 500、语义/embedding 类“不能表达为正则” 20、整条外语 4）；80 条外语模式、131 条无法表达或编译的模式（130 条语义类 + 1 条被 Hyperscan 和 PCRE2 同时拒绝的超大表达式）未进入引擎。
- 语言分布（启用规则）：en 325、mixed 16、zh 5、any 6。**中文覆盖薄弱是事实**（上游以英文为主），已用 12 条手工中文规则补充，仍需真实流量验证。
- 测试样例 3 859 条（上游 3 727 + 手工 132）；每条启用规则至少 1 正例 + 1 负例；Python 参考引擎复算：一致 3 495、不一致 0（部分转换/不可复算的另行标记）。
- 语料评估（Python 参考引擎，人工小语料，开发时参考过，**不是误报率/检出率估计**）：`reports/false_positive.md`、`reports/detection_eval.md`。

## 6. 调用（C）

```c
apg_context_t *ctx; apg_create((const uint8_t *)cfg, strlen(cfg), &ctx);           // cfg = {"manifest_path": ".../active.json"}
uint8_t *json; size_t len;
apg_scan_text(ctx, (const uint8_t *)text, strlen(text), "user_input", &json, &len); // 结果是 UTF-8 JSON
/* … 使用 json … */ apg_free_buffer(json);                                          // 必须用库的释放函数
apg_destroy(ctx);
```

契约（所有权、线程安全、错误码、热更新）见 **`docs/c-api.md`**；各语言示例见 `examples/`；集成建议见 `docs/embedding.md`。

## 7. 文档索引

| 文档 | 内容 |
|---|---|
| `docs/architecture.md` | 架构、数据流、规则/评分语义、归一化、设计决策 |
| `docs/sqlite-schema.md` | ER 图、表说明、触发器、示例 SQL、备份/WAL |
| `docs/rule-maintenance.md` | 导入上游更新、增改规则、质量闸门、发布/回滚、增加新来源 |
| `docs/c-api.md` | 完整 C ABI、JSON 请求/响应、内存生命周期、线程安全、错误码、热更新 |
| `docs/embedding.md` | 集成建议与各语言要点 |
| `docs/linux-testing.md` | Linux 实测步骤与验收清单 |
| `docs/windows-build.md` | Windows 构建、Hyperscan 风险、DLL 部署与调用 |
| `reports/PROGRESS.md` | 各阶段的实际完成情况与运行过的命令 |
| `reports/validation_matrix.md` | **已实测通过 / 实测失败 / 环境限制未测 / 待 Linux 执行 / 待 Windows 执行** |
| `reports/{coverage,source_inventory,false_positive,detection_eval,compatibility,build_matrix,performance,language_review}.md` | 覆盖、清点、误报/检出评估、兼容性、构建矩阵、性能计划、语言过滤审计 |

## 8. 已知限制与剩余工作（摘要，完整版在 `reports/PROGRESS.md`）

C++ 与 Hyperscan 全部待实测；Windows Hyperscan 获取与链接方式未验证；`.hsdb` 不可跨 Hyperscan 版本 / CPU / OS 移植（需在目标机器离线重编译）；中文规则覆盖薄、没有真实流量的误报评估；正则规则无法区分“引用攻击字符串的安全讨论”与真实攻击；7 个含 lookbehind 的上游模式被展开为定长分支并要求 PCRE2 复核（其中 2 个 Python `re` 无法编译，参考引擎对它们视为不命中，相关 11 条测试因此标为“不可复算”）——无法展开的变长 lookbehind 会被标为 unsupported（当前数据中为 0 条）；没有模糊测试；本项目自身许可证尚未选定。

## 9. 许可证与署名

规则来自 ATR（MIT）、trans-prompt-injection-detector（MIT）、prompt-injection-detection-rules（Apache-2.0），见 `LICENSES/NOTICE.md`（含修改说明）。本项目自写代码的许可证尚待项目负责人选定。
