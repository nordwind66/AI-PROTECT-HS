# AI Prompt Guard — 规则库

**SQLite 是规则的唯一权威来源**，加一套 Python 工具链（仅标准库，无需安装依赖）。负责：导入三个开源规则源（ATR、trans-prompt-injection-detector、prompt-injection-detection-rules，固定 commit）、维护手工中英文规则、校验、发布不可变的版本、导出规则快照 JSON，并提供与真实引擎做差分的测试。

规则库不依赖引擎源码。把已发布的版本变成 Hyperscan 规则包，用[引擎项目](../engine/)的 `ai-prompt-guard compile --snapshot`（本项目把它当黑盒命令，用 `--cli` 或 `APG_CLI` 指定）。

## 当前规则集

已发布的最新版本是 **1.1.3**：533 条规则、2135 个模式；其中含中文模式的规则 190 条（英文规则按攻击意图改写出 154 条中文规则，对应关系见 `reports/zh_conversion_map.md`）。数据库 `data/ai_prompt_rules.db`，指纹 `data/ai_prompt_rules.db.sha256`。

## 日常更新

```bash
bash scripts/release.sh --dry-run                            # 改 data/manual_rules/*.json 后先看会改什么
bash scripts/release.sh --cli /path/to/ai-prompt-guard       # 一条命令：同步 → 规则样例 → 严格校验 → 发布下一个补丁版本 → 编译 → 登记激活 → 打包
```

规则名是主键（新名字=新规则，同名有变化=新修订）；没有变化时什么都不发布、不编译。分步命令：`tools/update_rules.py`（发布）、`scripts/compile.sh`（编译）、`scripts/package.sh`（打包）；详见 `docs/rule-maintenance.md`。

## 测试

```bash
bash scripts/test.sh                                         # 工具链单元测试（参考引擎、导入器、数据库、规则样例、语料预期）
bash scripts/test.sh --engine <引擎>/build --backend hyperscan    # 再加：用真实引擎做端到端与差分（在临时数据库副本上）
python3 tools/diff_hyperscan.py --lib <引擎>/build/bin/libai_prompt_guard.so --manifest dist/linux/x86_64/<版本>/manifest.json --version <版本>
```

## 脚本

| 脚本 | 作用 |
|---|---|
| `scripts/release.sh` | 规则变了：一条命令到规则包 |
| `scripts/compile.sh` | 已发布版本 → 导出快照 → 引擎编译器 → 登记 → 激活（写 `active.json`） |
| `scripts/package.sh` | 规则包 `.tar.gz`（`<版本>/` + `active.json`） |
| `scripts/test.sh` | 测试 |
| `scripts/rebuild_db.sh` | 从锁定的上游 commit 从零重建规则库（很少用） |

## 目录与文档

```text
data/      权威规则库 · manual_rules/*.json（手工规则）      sql/       SQLite schema（含不可变性触发器、视图）
tools/     rules.py · apg_rules/ · sources/ · update_rules.py · build_rules_db.py · diff_hyperscan.py · gen_unicode_tables.py
third_party/  三个上游仓库的干净快照与 commit 锁              schemas/   规则规格、快照、活动指针的 JSON Schema
tests/     python/ · corpus/（语料与预期结果）· e2e/ · fixtures/   scripts/  release · compile · package · test · rebuild_db
reports/   覆盖、清点、误报/检出评估、转换对应表、PROGRESS.md      LICENSES/  上游许可证与署名
```

| 文档 | 内容 |
|---|---|
| `docs/architecture.md` | 规则库架构、数据流、规则模型（规则 / 条件 / 正则三层）、版本与产物 |
| `docs/rule-maintenance.md` | 导入上游更新、增改规则、质量闸门、发布/编译/回滚、增加新来源 |
| `docs/sqlite-schema.md` | ER 图、表说明、触发器、示例 SQL、备份/WAL |

## 许可证与署名

规则来自 ATR（MIT）、trans-prompt-injection-detector（MIT）、prompt-injection-detection-rules（Apache-2.0），见 `LICENSES/NOTICE.md`（含修改说明）。
