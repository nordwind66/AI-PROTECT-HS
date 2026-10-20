# 规则维护手册

读完本文，另一位研发应当能够：**导入第三方更新、查询 SQLite、修改规则、发布版本、编译出规则包并打包**。
所有规则管理命令都是 `python tools/rules.py …`（只用 Python 标准库，Python ≥ 3.8；全局选项 `--db FILE` / `--actor NAME` 可以写在子命令之前或之后）。

规则库是一个独立项目，不包含引擎。把已发布的版本变成 Hyperscan 规则包，要用**引擎项目**的 `ai-prompt-guard compile`（下文用 `--cli` / `APG_CLI` 指定它）；引擎怎么构建见引擎项目的文档。

## 0. 日常更新：改 JSON → 跑一个脚本（推荐）

规则库只需要生成一次（`build_rules_db.py --fresh`，见 §2）。之后维护**手工规则**只做两件事：

1. 在 `data/manual_rules/*.json` 里增加或修改规则（格式见 `zh_extra.json`：`name`、`category`、`severity`、`patterns`、`tests` 的正反样例……）。**规则名是主键**：新名字 = 新规则；同名 = 对比后有变化就生成新修订；改名 = 新规则（旧的用 `--prune` 删除）。
2. 运行：

```bash
python tools/update_rules.py --dry-run     # 先看会新增/修改哪些规则，不写任何东西
python tools/update_rules.py               # 同步 → 规则测试 → 严格校验 → 发布下一个补丁版本(如 1.1.0 → 1.1.1) → 刷新语料期望值 → 校验和
python tools/update_rules.py --compile --cli /path/to/ai-prompt-guard   # 同上，再导出快照、用引擎的编译器编译、登记、激活（等价于随后跑 scripts/compile.sh）
bash scripts/release.sh --cli /path/to/ai-prompt-guard                  # 以上全部 + 打包，一条命令
```

选项：`--version 1.2.0` 指定版本；`--prune` 同时删除 JSON 里已经没有的手工规则；`--file a.json b.json` 只用指定文件（此时不要配 `--prune`）；`--no-eval` 不刷新 `tests/corpus/expected/*`。文件内容与上一个版本完全一致时什么都不发布。已发布的版本永远不变，要回退用 `rules.py rollback`。

底层是 `rules.py sync-manual`（可单独使用，也支持 `--dry-run` / `--prune`）。上游规则（ATR / fevzi / trans）不受影响，它们仍然用 `rules.py import` 更新。

## 1. 工作流一览

```mermaid
flowchart TD
  A["sources sync --locked<br/>(复现锁定 commit)"] --> B["import / add<br/>(规则进入草稿，已发布版本不受影响)"]
  B --> C["verify-tests · validate --strict · eval<br/>(质量闸门)"]
  C --> D["publish --version X<br/>(不可变版本 + 规范快照)"]
  D --> E["export-snapshot → 引擎的 ai-prompt-guard compile --snapshot<br/>(生成 .hsdb + manifest)"]
  E --> F["register-artifact"]
  F --> G["activate --pointer-dir …<br/>(运行指针 active.json)"]
  G -.出问题.-> H["rollback --to 旧版本"]
```

**核心规则**：`import / add / update / enable / disable / delete` 只改“当前头部”，**永远不会改动已发布的版本**。只有 `publish` 之后再 `compile`，修改才会进入运行时。

## 2. 从零构建规则库（可重复）

```bash
python tools/rules.py sources sync --locked     # 按 third_party/sources.lock.json 物化三个上游仓库（需要 git；缺失时才联网）
python tools/build_rules_db.py --fresh          # ≈17 秒：init → import all → add 手工规则 → verify-tests → validate --strict → publish 1.1.0 → 报告 → db check
```

`build_rules_db.py` 的每一步都是普通的 `rules.py` 命令，可以手工逐步执行；完整输出保存在 `reports/build_rules_db.log`。两次全新构建得到**逐字节相同的快照**（SHA-256 `34e6d9af…527a7a`，1 679 307 字节）；数据库文件本身含时间戳，字节不同，`data/ai_prompt_rules.db.sha256` 只是交付指纹。

## 3. 查询

```bash
python tools/rules.py list --lang zh,mixed                          # 表格；--format csv|json
python tools/rules.py list --category jailbreak --status enabled --severity critical,high
python tools/rules.py list --source atr --text "persona"              # 来源 / 名称或 ID 子串
python tools/rules.py show --id AIPS-IO-0032                          # 规则、模式、来源、修订、测试
python tools/rules.py show --id AIPS-IO-0032 --json
python tools/rules.py versions                                         # 版本、规则数、产物数、ACTIVE
python tools/rules.py diff --versions 1.0.0 1.1.0                      # 两个版本之间的差异
python tools/rules.py explain --text "手机怎么进入开发者模式？"            # 为什么命中/没命中（Python 参考引擎）
python tools/rules.py explain --corpus tests/corpus/benign_extended.jsonl --id z064
```

任何 SQLite 客户端都可以直接查（示例见 `docs/sqlite-schema.md` §4）。**不要直接 UPDATE/DELETE 业务表**：触发器会拒绝对不可变表的修改，而直接改 `rules` 等表会绕过修订与审计。

## 4. 新增 / 修改 / 启停 / 删除

### 4.1 新增手工规则

规则写在 JSON 里（Schema：`schemas/rule_spec.schema.json`，真实例子：`data/manual_rules/zh_core.json`、`en_core.json`）：

```json
{
  "rules": [{
    "name": "中文：忽略之前的指令",
    "category": "instruction_override",
    "severity": "high", "weight": 0.7, "confidence": 0.8,
    "patterns": [
      {"key": "p1", "regex": "(?:忽略|无视)[^\\n]{0,8}?(?:之前|以前)[^\\n]{0,8}?(?:指令|规则)"},
      {"key": "p2", "regex": "ignore\\s+previous\\s+instructions", "flags": "i"}
    ],
    "condition": "any",
    "tests": {"positive": ["忽略之前的所有指令"], "negative": ["请忽略这个编译警告"]}
  }]
}
```

```bash
python tools/rules.py add --file my_rules.json --dry-run     # 先看会创建什么（事务回滚）
python tools/rules.py add --file my_rules.json
python tools/rules.py verify-tests                            # 样例与模式是否一致（Python oracle）
python tools/rules.py validate --strict                       # 警告也算失败：每条启用规则至少一个正例和一个负例
```

要点：

- 模式用 **PCRE 方言**，按与上游模式相同的流程转换并分类（`hs_native` / `hs_prefilter_pcre2`）；可匹配空串、无效、被语言作用域改写的模式会**整份文件被拒绝**，不会写入一半。
- `condition` 可以是 `"any"`（默认）、`"all"` 或条件树（叶子 id = 模式 `key`），支持 `not`。
- `field` 默认 `content`（所有来源都提供）。需要只看某个字段时用 `user_input`/`tool_response`/`tool_name` 等（见 `docs/c-api.md` §请求字段）。
- `scope: "translation_only"`（等价于 `context_requires: {"task": "translation"}`）：只有调用方声明了该上下文才会生效，否则只出现在 `needs_context` 里。
- 同名手工规则再次 `add` 是 no-op（幂等）。
- 每条规则的 ID（`AIPS-<类别码>-NNNN`）是稳定的，由 `id_counters` 分配，永不复用。

### 4.2 修改

```bash
python tools/rules.py update --id AIPS-JB-0109 --set confidence=0.3 --set description="..." --reason "合法角色扮演误报"
python tools/rules.py disable --id AIPS-JB-0109 --reason "..."     # enable 恢复；delete 是软删除，enable 可恢复
python tools/rules.py restore-upstream --id AIPS-JB-0109             # 丢弃本地修改，按上游当前定义重新推导（新修订）
```

可通过 `--set` 修改的键：`name category lang severity weight confidence default_action scope context_requires score_group description tags`。**模式本身不可变**——要改正则，新增一条手工规则并停用旧规则（或用 §6 的质量排除）。每次修改产生新修订（谁、何时、为什么、前后 hash），`modified_locally=1`。

## 5. 导入第三方更新

```bash
python tools/rules.py sources sync --update            # 把锁移动到各分支当前 head（联网；会重写 sources.lock.json 与 LICENSES 副本）
python tools/rules.py import --dry-run --detail         # 只计算计划：新增/变化/未变/上游删除，列出每条变化
python tools/rules.py diff                              # 同上（数据库 vs 当前锁定的上游）
python tools/rules.py import                            # 应用；--strict：提取器有任何警告就中止
python tools/rules.py verify-tests && python tools/rules.py validate --strict
python tools/rules.py publish --version 1.1.0 --notes "ATR 7c6f9ca → <new>"
```

行为：

| 情况 | 处理 |
|---|---|
| 新的上游规则 | 新稳定 ID、第一个修订、溯源、测试 |
| 上游规则变化 | 未被本地修改 → 新修订（`import_update`）；**被本地修改过 → 保留本地版本并记一条 `merge_conflict` 警告**（`rule_issues`），由人决定 `restore-upstream` 还是保留 |
| 上游删除 | 规则置为 `deprecated`（不再进入新版本），历史保留 |
| 上游改成“排除/不支持” | 同样置为 `deprecated`，原因写入 `rule_issues` |
| 同一来源导入两次 | 完全幂等（内容 hash 相同 → `unchanged`），不产生重复修订 |
| 来源与锁不一致 | `import` 拒绝（`--allow-unlocked` 可强制，不建议） |

`sources.lock.json` 记录每个来源的仓库、分支、**完整 commit**、提交时间、许可证 SPDX、每个文件的 git blob 与 SHA-256、整棵树 hash；`sources verify` 重新计算并比较。

## 6. 本地质量决策（透明、可复现）

上游规则里偶有对**普通中文/英文**过宽的模式（例如把“进入开发者模式”这种手机设置说明当作越狱）。本项目不悄悄改写上游，而是把本地决定写成**可审计的数据**，随导入一起复现：

| 位置 | 内容 | 效果 |
|---|---|---|
| `tools/sources/atr_policy.py` · `PATTERN_EXCLUSIONS` | `(ATR 规则 id, 条件位置) → 原因` | 该条件的 fate 记为 `excluded_scope`，原因以 `local_quality:` 开头；规则其余部分照常导入（`decision = partial`）。当前 5 条，见 `docs/sqlite-schema.md` 查询 4.13 |
| `tools/sources/atr_policy.py` · `ENGINE_LIMIT_EXCLUSIONS` | `(ATR 规则 id, 条件位置) → 原因` | 该条件的 fate 记为 `unsupported`，原因以 `engine_limit:` 开头；**只收录在真实机器上观察到的**：Hyperscan（原生与预过滤）和 PCRE2 都编译不了、`compile` 只能隔离的表达式。规则其余部分照常导入。当前 1 条（ATR-2026-01005 的 Q/A 链条件），证据见 `reports/logs/linux_init_rules_2026-10-17.log` |
| `tools/sources/atr_policy.py` · `EXCLUDE_*` / `INCLUDE_OTHER` | ATR 目录之外/之内哪些规则属于“提示词文本攻击”范围 | 范围外规则记为 `excluded_scope` 并保留原因（500 条） |
| `tools/sources/trans_pid.py` · `GROUP_POLICY` | trans 检测器各组 → 类别、适用范围、置信度 | 三个“通用”组（prompt_leak / roleplay_bypass / cn_mixed_roleplay）置信度 0.38，使单个弱命中不会到 `review` |
| `tools/apg_rules/publish.py` · `SCORING_DEFAULTS` | 阈值、来源系数、风险等级、`needs_context_review_at` | 写进每个发布快照，版本间可对比 |
| `data/manual_rules/*.json` | 项目自写的中文/英文补充规则（13 条） | `origin=manual`，各自带正负例 |

修改这些文件后必须重新 `import`（会生成新的修订并出现在 `diff` 里）、重新 `publish`。**每项决定都应当有语料证据**：`tests/corpus/` 里的误报样例 + `rules.py explain` 的追踪。

## 7. 质量闸门

| 命令 | 检查什么 |
|---|---|
| `verify-tests` | 用 Python 参考引擎复算每条测试样例；不一致记 `python_oracle_mismatch`，**部分转换的规则**（语言裁剪过）的不一致记为 `skipped_scope`，不会静默通过 |
| `validate [--strict]` | 引用完整性、条件树、字段、模式分类、每条启用规则至少 1 正例 + 1 负例、重复规则候选（info）；`publish` 之前自动执行（有 error 则拒绝） |
| `eval --report [--write-expected]` | 对 `tests/corpus/*` 与上游翻译数据集计算决策；`--write-expected` 写出 `tests/corpus/expected/*.expected.jsonl`（C++ 差分测试的预期）；`--report` 写 `reports/false_positive.md`、`reports/detection_eval.md` |
| `db check` | SQLite 完整性、外键、migration 校验和、审计哈希链 |

> Python oracle ≠ C++ 引擎。它证明“转换和规则语义自洽”，不证明 Hyperscan/PCRE2 的行为；后者靠用真实引擎做的差分测试（`tests/e2e/run_e2e.py`、`tools/diff_hyperscan.py`）。

## 8. 发布、编译、激活与回滚

```bash
python tools/rules.py stage --version 1.1.0-rc1            # 草稿版本（可检查快照：export-snapshot），不可激活
python tools/rules.py publish --version 1.1.0 --notes "…"  # 冻结；版本只能前进；内容与上一版完全相同则拒绝
python tools/rules.py export-snapshot --version 1.1.0 --out /tmp/snap.json    # 编译器消费的精确字节

# 用引擎项目的编译器编译（用与你部署的引擎同一份 Hyperscan 的 ai-prompt-guard；CPU、操作系统与运行机器一致）：
ai-prompt-guard compile --snapshot /tmp/snap.json --out dist --backend hyperscan --cpu-target generic
python tools/rules.py register-artifact --manifest dist/linux/x86_64/1.1.0/manifest.json
python tools/rules.py activate --version 1.1.0 --reason "release" --pointer-dir dist/linux/x86_64
bash scripts/package.sh                                      # 打成规则包 dist/package/ai-prompt-guard-rules-1.1.0-linux-x86_64.tar.gz
# 运行进程里：apg_reload(ctx, "dist/linux/x86_64/active.json")   → 原子切换；失败则旧规则集继续服务

python tools/rules.py rollback --to 1.0.0 --reason "误报回归" --pointer-dir dist/linux/x86_64   # 只移动指针，写审计
```

- `compile` 在**临时目录**里构建并做加载自检，通过后才原子改名；已存在的输出目录需要 `--force`。
- **并行与耗时**：Hyperscan 编译是整个构建里最慢的一步，`compile` 默认用本机所有 CPU 线程（最多 16 个），并每几秒在 stderr 打印进度（已完成多少条、当前最慢的是哪条、已用时间）。流程分两段：① 每条正则**单独并行**编译，每次尝试有时限；被拒绝或超时的依次降级为预过滤、再放宽大范围重复，仍失败才隔离，**不会因为一条失败而整体重编**；② 通过的模式按编译耗时均衡分成若干分片，每片一次 `hs_compile_multi`，各片并行编译，产物为 `rules.<profile>.01.hsdb`、`rules.<profile>.02.hsdb` …（只有一片时仍叫 `rules.<profile>.hsdb`）。运行时依次扫描同一 profile 的所有分片并合并命中。
- 选项（均可省略）：`--jobs N` 工作线程数（`1` = 严格串行）；`--shards N` 每个 profile 的分片数；`--native-timeout SEC` 仍有“放宽形式”可以兜底的尝试的时限（默认 15 秒：原生编译超过它的模式本来就更适合走预过滤——库更小、构建更快）；`--pattern-timeout SEC` 最后一次机会的时限，超过则隔离该模式（默认 60 秒）；`--shard-timeout SEC` 单个分片的时限（默认 1800 秒，超时则对半拆分重试）；`--relax-repeat N` 把大于 N 的计数重复 `{m,n}` 放宽成 `{m,}`（超集，PCRE2 逐个复核；默认 32，`0` = 关闭）：Hyperscan 在 UTF-8 模式下无法原生编译带大范围重复的模式（报 “Pattern is too large”，而且要很久才报），所以含大于 2N 的重复的模式**直接**用放宽后的预过滤形式编译，其余模式在原生、预过滤都失败后才把它作为最后一招。`scripts/compile.sh`（导出快照 → 编译 → 登记 → 激活，一条命令）会把这些选项原样转给 `compile`。
- 假设与风险（**未经实测**）：并行编译假定 Hyperscan 的 `hs_compile*` 可被多个线程同时调用（它没有共享的可变状态；若你的版本不是这样，用 `--jobs 1`）；每个并发编译都要占内存，内存紧张时调小 `--jobs`；Hyperscan 无法中断一次编译，超时的线程会被放弃（继续占用 CPU 直到它自己返回或进程退出），数量超过上限时 `compile` 会明确报错而不是悬挂。
- `--strict`：只要有模式被隔离就失败。默认会隔离并在 `build_report.json` 列出（错误原文、使用它的规则 ID、上游溯源），`manifest.status = partial`。
- `.hsdb` 由编译它的那一版 Hyperscan 加载，不可跨 OS 使用；Hyperscan 会拒绝不兼容的数据库。部署的引擎换了 Hyperscan 版本时，用新引擎的 `ai-prompt-guard` 把同一份已发布快照重新编译即可，规则本身不用改。
- 回滚需要旧版本的产物仍在 `dist/` 里并已登记；否则先 `compile` 旧版本。

## 9. 增加第四个规则来源

1. 在 `third_party/sources.def.json` 里新增来源（仓库、分支、许可证、`importer`、`include_paths`）；`sources sync --update` 锁定。
2. 在 `tools/sources/` 写一个 `SourceImporter` 插件（参考 `fevzi_pidr.py`，约 150 行）：把上游规则变成 `SrcRule`（含 `SrcPattern`、可选条件树、`SrcTest`、`UnifiedHint`），**不执行上游代码**，每个排除/不支持的决定都写原因；在 `tools/sources/__init__.py` 注册。
3. 复制许可证到 `LICENSES/`，更新 `LICENSES/NOTICE.md`。
4. `import --source <id> --dry-run` → `import` → `verify-tests` → `validate --strict`。引擎和 schema **不需要改**。

## 10. 常见问题

| 现象 | 原因 / 处理 |
|---|---|
| `materialised sources do not match sources.lock.json` | `third_party/sources` 被改动或缺失：`sources sync --locked` |
| `migration … was modified after it was applied` | 改了已应用的 migration；新增 `sql/00N_*.sql`，不要改旧的 |
| `publish`: `identical to version X` | 草稿内容与上一版完全相同，没有东西可发布 |
| `publish`: `versions only move forward` | 版本号必须大于所有已有版本；要回退用 `rollback` |
| `validate --strict` 失败于缺少样例 | 给规则补正例/负例（`tests` 字段） |
| 某条上游规则没有出现 | `rules.py show` 不到时查 `source_rules`（`decision`/`decision_reason`）：被范围排除、语言排除或属于语义类方法 |
| Windows 控制台中文乱码/崩溃 | 用 `python -X utf8`；工具内部已对输出做 `errors="replace"` |
