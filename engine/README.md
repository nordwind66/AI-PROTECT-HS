# AI Prompt Guard — 检测引擎

进程内的检测库（C++17 核心，稳定的 **C ABI**，同一份源码构建 Linux `.so` 与 Windows `.dll`）和命令行工具 `ai-prompt-guard`。引擎只做三件事：

1. **初始化** `apg_create(配置)`：读取规则包（目录：`manifest.json` + `rules.*.hsdb` + `ruleset.meta.json`），加载规则；
2. **检测** `apg_scan_text / apg_scan_json`：归一化 → Hyperscan 批量匹配 → PCRE2 复核 → 条件求值与评分，返回 JSON（命中的规则、类别、严重度、风险分、决策、命中的原文片段与所在句子）；
3. **热更新** `apg_reload`：换一个规则包，在途扫描不受影响。

引擎不依赖规则库：没有 SQLite，没有 Python。规则从哪里来、怎么写，是 [`../rules`](../rules/) 项目的事；两者之间只有规则快照 JSON（编译器输入）和规则包目录（编译器输出、引擎输入）。支持中文、英文与中英混合文本。

## 构建与测试

```bash
bash scripts/setup.sh              # 一次性：检查工具，编译静态（-fPIC）Hyperscan 5.4.2 到 .deps/hyperscan（--install 先装缺的系统包，--check 只检查）
bash scripts/build.sh              # 默认就是交付形态：Hyperscan、PCRE2、libstdc++ 静态链进 libai_prompt_guard.so，目标机只需要 glibc → build/
bash scripts/test.sh               # C++ 单元测试 + Schema 与静态检查（不需要规则库）
bash scripts/package.sh            # 引擎包 → dist/ai-prompt-guard-engine-<版本>-linux-x86_64.tar.gz（含 check.sh）
bash scripts/bench.sh --manifest <规则包>/active.json     # 基准（显式运行，需要自己指定规则包）
```

`build.sh` 的变体：`--system-libs`（动态链接系统的 libhyperscan-dev / libpcre2-dev，输出 `build-system/`）、`--no-hyperscan`（只有显式的 `pcre2_fallback` 后端，不需要 Hyperscan，`build-fallback/`）、`--asan`（Debug + ASan/UBSan，`build-asan/`）；`--hs DIR`、`--out DIR`、`--jobs N`、`--clean`。Windows：`scripts/build.ps1`、`scripts/test.ps1`，见 `docs/windows-build.md`。

## 命令行

```text
ai-prompt-guard compile   --snapshot FILE [--out DIR] [--backend hyperscan|pcre2_fallback] [--cpu-target generic|host] [--jobs N] [--shards N] …
ai-prompt-guard verify    --manifest FILE        # 完整校验规则包（哈希、平台、版本）
ai-prompt-guard info      --manifest FILE
ai-prompt-guard scan      --manifest FILE --text "…" [--source user_input|agent_message|tool_output|rag_document]
ai-prompt-guard scan-batch --manifest FILE --requests FILE.jsonl
ai-prompt-guard bench     --manifest FILE --dataset DIR            # 显式基准，从不自动运行
```

`--manifest` 可以是规则包里的 `manifest.json`，也可以是指向当前版本的 `active.json`。

## 调用（C）

```c
apg_context_t *ctx; apg_create((const uint8_t *)cfg, strlen(cfg), &ctx);           // cfg = {"manifest_path": ".../active.json"}
uint8_t *json; size_t len;
apg_scan_text(ctx, (const uint8_t *)text, strlen(text), "user_input", &json, &len); // 结果是 UTF-8 JSON
/* … 使用 json … */ apg_free_buffer(json);                                          // 必须用库的释放函数
apg_destroy(ctx);
```

配置默认**不校验**规则包的哈希、版本、平台（`verify_ruleset=false`），Hyperscan 会拒绝它无法使用的数据库；需要完整校验时设 `"verify_ruleset": true` 或运行 `ai-prompt-guard verify`。

## 目录与文档

```text
include/ai_prompt_guard.h   唯一的公共 C ABI        src/{core,ruleset,api}/   引擎源码（ruleset/compiler.cpp 是规则编译器）
cli/                        ai-prompt-guard         examples/                  C · C++ · dlopen · LoadLibrary · Python · Go · Rust · scan_loop · bench_live
schemas/                    配置/请求/响应/manifest/… 的 JSON Schema        tests/    cpp/（单元测试）· python/（Schema 与静态检查）· corpus/（基准用语料）
scripts/                    setup · build · test · bench · package（.sh）· build/test（.ps1）
```

| 文档 | 内容 |
|---|---|
| `docs/architecture.md` | 引擎架构、编译器、运行期数据流、评分与归一化语义 |
| `docs/c-api.md` | 完整 C ABI、JSON 请求/响应、内存生命周期、线程安全、错误码、热更新 |
| `docs/embedding.md` | 集成建议、自包含动态库、部署布局 |
| `docs/linux-testing.md`、`docs/windows-build.md` | 构建与测试步骤 |
| `reports/` | 构建矩阵、兼容性、性能计划、验证矩阵与历史日志 |
