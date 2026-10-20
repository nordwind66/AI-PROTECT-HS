# AI Prompt Guard

提示词注入检测，由两个**互相独立**的项目组成：

| 项目 | 内容 | 什么时候动它 |
|---|---|---|
| [`engine/`](engine/) | 检测引擎：C++17 进程内库（稳定 C ABI，Linux `.so` / Windows `.dll`）+ 命令行 `ai-prompt-guard`。初始化时读取规则包，检测时用 Hyperscan 匹配并评分 | 引擎代码变了：只重新构建引擎 |
| [`rules/`](rules/) | 规则库：SQLite 权威规则库 + Python 工具链（导入、手工规则、校验、发布、参考引擎、语料与差分测试） | 规则变了：只升级规则，编出新的规则包 |

两者各自构建、测试、发布，没有源码依赖，也不要求对方的版本号。它们之间只有两份文件：

```
规则库项目                          引擎项目
rules.py export-snapshot            ai-prompt-guard compile --snapshot
  → 规则快照 JSON  ───────────────────►  → 规则包目录（manifest.json · rules.*.hsdb · ruleset.meta.json）
                                                   │
                                                   ▼
                                  apg_create(规则包) / apg_scan_text(文本) / apg_reload(新规则包)
```

编译器（把快照变成 Hyperscan 数据库）属于引擎项目，因为 `.hsdb` 只能由编译它的那一版 Hyperscan 加载；规则库项目把它当黑盒命令使用（`--cli` 或环境变量 `APG_CLI`）。引擎默认不对规则包做版本、哈希、平台校验，Hyperscan 自己会拒绝不兼容的数据库。

## 日常操作

**引擎代码变了**

```bash
cd engine
bash scripts/linux/build.sh --static --hyperscan-root <静态 Hyperscan 前缀> --build-dir build/linux-static
bash scripts/linux/test.sh --build-dir build/linux-static      # 引擎自己的测试，不需要规则库
bash scripts/linux/package.sh                                   # 引擎包：lib + include + bin + examples
```

已有的规则包不用重编，换上新的 `.so` 即可（Hyperscan 版本没变时）。

**规则变了**

```bash
cd rules
python tools/update_rules.py --dry-run                          # 改 data/manual_rules/*.json 后先看会改什么
python tools/update_rules.py --compile --cli <引擎>/build/linux-static/bin/ai-prompt-guard
bash scripts/linux/package_rules.sh                             # 规则包：<版本>/ + active.json
```

宿主程序里 `apg_reload(ctx, "<规则包>/active.json")` 热更新，不用重启，也不用重新编译引擎。

## 目录

```text
engine/   include/ src/{core,ruleset,api} cli/ examples/ schemas/ scripts/ tests/ docs/ tools/
rules/    data/ sql/ tools/ third_party/ schemas/ tests/ scripts/ docs/ reports/ LICENSES/
```

各项目的细节见 [`engine/README.md`](engine/README.md) 与 [`rules/README.md`](rules/README.md)。需要拆成两个仓库时，`git subtree split -P engine` 与 `git subtree split -P rules` 各取一份，两个项目之间没有相对路径依赖（`rules/` 里的 `tools/gen_unicode_tables.py` 默认往相邻的 `engine/` 写生成物，用 `APG_ENGINE_DIR` 可改；`tests/e2e` 同理用它找引擎的 schema 与示例）。
