# C ABI 参考（`include/ai_prompt_guard.h`，ABI 1.0.0）

> **状态**：头文件、实现（`engine/api/apg_api.cpp`）、示例均已完整编写并经过人工逐行审查，但 **从未被编译或运行**（待 Linux / Windows 实测，见 `reports/validation_matrix.md`）。本文是契约；与代码不一致时以头文件为准，并请把差异当成缺陷提交。

**唯一**的公共接口是 `include/ai_prompt_guard.h`，Linux `.so` 与 Windows `.dll` 来自同一份源码、同一份头文件。

## 1. 链接与加载

| 平台 | 产物 | 链接方式 |
|---|---|---|
| Linux x86-64 | `libai_prompt_guard.so`（SONAME `.so.1`）、`libai_prompt_guard.a` | `-lai_prompt_guard`；或 `dlopen` + `dlsym`（`examples/linux/dlopen.c`）。导出符号**只有** `apg_*`（GNU version script `APG_1.0`） |
| Windows x64 | `ai_prompt_guard.dll` + `ai_prompt_guard.lib`（导入库） | 链接 `.lib`；或 `LoadLibraryW` + `GetProcAddress`（`examples/windows/load_library.cpp`）。`__declspec(dllexport/dllimport)` 与 `__cdecl` 由头文件宏 `APG_API` / `APG_CALL` 给出 |
| 静态链接（Windows） | `ai_prompt_guard_static.lib` | 编译调用方时定义 `APG_STATIC` |

x86-64 only（本版不支持 ARM / 32 位 / macOS）。DLL 依赖的 Hyperscan、PCRE2、VC 运行库必须在 DLL 同目录或进程 DLL 搜索路径上。

## 2. 版本与兼容

- `apg_abi_version()` 返回 `(major<<16)|(minor<<8)|patch`，是**库构建时**的 ABI。调用方必须检查 `(apg_abi_version() >> 16) == APG_ABI_VERSION_MAJOR`，且库的 minor ≥ 头文件的 `APG_ABI_VERSION_MINOR`。
- major 变化 = 二进制不兼容；minor 只会**追加**函数；已有函数签名在同一 major 内不会变。
- JSON 文档有各自独立的 `schema_version`（现为 1），见 `schemas/`。
- 规则集产物自带的版本信息（manifest 的 `engine.abi_version`、归一化表版本、Hyperscan 版本串、CPU 特性、OS/架构、各文件 SHA-256）默认**不校验**：引擎只管读取规则、加载规则，Hyperscan 自己会拒绝版本或 CPU 特性不兼容的数据库（`APG_ERR_VERSION` / `APG_ERR_PLATFORM`）。需要完整校验时配置 `verify_ruleset=true`，或运行 `ai-prompt-guard verify`。

## 3. 函数

所有函数都在 `extern "C"` 内，**内部捕获全部 C++ 异常**；不会让异常穿过 ABI。出参在做任何可能失败的事情之前先被置为 `NULL/0`。

### 标识

```c
uint32_t    apg_abi_version(void);
const char *apg_engine_version(void);                 // 如 "1.0.0"，静态存储，勿释放
const char *apg_status_string(apg_status_t status);   // "APG_OK" …，静态存储
const char *apg_last_error(void);                     // 本线程最近一次失败调用的诊断（UTF-8，永不为 NULL；成功时为空串）
```

`apg_last_error()` 是**线程本地**的，指针在本线程下一次 `apg_*` 调用之前有效。

### 生命周期

```c
apg_status_t apg_create(const uint8_t *config_json, size_t config_len, apg_context_t **out_ctx);
apg_status_t apg_reload(apg_context_t *ctx, const char *manifest_path_utf8);
void         apg_destroy(apg_context_t *ctx);          // NULL 允许
```

- `apg_create`：解析并**严格校验**配置（未知键 → `APG_ERR_CONFIG`），加载 manifest 与各分片，反序列化数据库（默认不做哈希/版本/平台校验，由 Hyperscan 自己拒绝不可用的数据库；`verify_ruleset=true` 时才做完整校验），创建首个 scratch，构建不可变的规则快照。**不打开 SQLite，不编译任何正则。** 失败时 `*out_ctx == NULL`。
- `apg_reload`：新规则集**完整**加载并校验（包括创建 scratch）之后才原子替换；在途扫描继续用旧规则集；失败时旧规则集原样保留并返回错误码。路径可以是 `manifest.json`，也可以是 `active.json` 指针文件。
- `apg_destroy`：阻塞到“在它之前已经开始”的扫描/重载结束。调用方必须保证没有线程在它之后（或与它并发地）**开始**新调用——那是对已销毁句柄的使用，任何 C API 都无法防御。

### 扫描

```c
apg_status_t apg_scan_text(apg_context_t *ctx, const uint8_t *utf8, size_t utf8_len, const char *source,
                           uint8_t **out_json, size_t *out_len);
apg_status_t apg_scan_json(apg_context_t *ctx, const uint8_t *request_json, size_t request_len,
                           uint8_t **out_json, size_t *out_len);
apg_status_t apg_get_info(apg_context_t *ctx, uint8_t **out_json, size_t *out_len);
void         apg_free_buffer(void *ptr);               // NULL 允许
```

- `apg_scan_text`：高频入口。`utf8` 带**显式字节长度**（可含 `U+0000`，被当作可忽略字符）；`utf8` 仅当 `utf8_len==0` 时可为 `NULL`；`source` 为 NUL 结尾的 `"user_input"|"tool_output"|"rag_document"|"agent_message"`，`NULL` 等于 `user_input`。
- `apg_scan_json`：结构化入口（`schemas/request.schema.json`），支持 `request_id`、命名字段 `fields`、上下文 `context`。两个入口共享同一套检测与决策逻辑。
- **关于文本本身的问题**（非法 UTF-8、超过 `limits.max_text_bytes`、候选命中过多）**不是** API 失败：函数返回 `APG_OK`，结果 JSON 里 `status:"error"`、`error_code`、`decision`（取自 `policy.on_error`，默认 `review`）。API 失败（`!= APG_OK`）只用于：参数错误、请求 JSON 本身不合法/超过 `max_request_bytes`、内存不足、内部错误。
- 返回的 JSON 缓冲区由**库的分配器**分配（`malloc`）并附加 `NUL` 结尾；`*out_len` 不含结尾 NUL。**必须用 `apg_free_buffer` 释放**，不得用 `free()`/`delete`（Windows 上调用方与 DLL 可能使用不同的 CRT）。失败时 `*out_json=NULL, *out_len=0`。
- `apg_get_info`：引擎/ABI/规则集版本、哈希、后端（hyperscan 或 pcre2_fallback）、Hyperscan/PCRE2 版本、模式/规则数量、被隔离模式、策略与限额（`schemas/info.schema.json`）。

### 3.1 不需要释放内存的接口（ABI 1.1 新增）

高并发（例如每个 HTTP 请求扫一次）时可以不用 `apg_free_buffer`：

| 函数 | 作用 |
|---|---|
| `apg_scan_text_verdict(ctx, utf8, len, source, &verdict)` | **最便宜**：只返回结论（`decision`、`score`、命中规则数），写进调用方的 `apg_verdict_t`。不生成 JSON，不定位举证文本，没有任何需要释放的东西。检测结果与 `apg_scan_text` 完全相同 |
| `apg_scan_text_hits(ctx, utf8, len, source, hits, hits_cap, &verdict)` | **只要“规则编号 + 命中文本”时用它**：调用方给一个 `apg_hit_t hits[N]` 数组（例如 8 个），引擎写入 `min(命中规则数, N)` 条，风险最高的在前，每条规则一条：`rule_id`（如 `AIPS-PI-0009`）和 `matched_text`（原文里命中的片段，最长 255 字节，在字符边界截断）。`verdict.matched_rules` 是命中规则的总数，大于 N 说明放不下。无 JSON、无分配、无需释放，规则与分数和 `apg_scan_text` 一致 |
| `apg_match_text(ctx, utf8, len, source, min_risk, &match)` | **只要“有没有命中、命中了哪条”时用它（最快）**：命中第一条规则就结束，**包括 Hyperscan 扫描本身也在第一个满足条件的规则出现时立即停止**，不再扫描剩余文本和后续视图。结果写进调用方的一个 `apg_match_t`：`matched`（1/0）、`scan_error`、`rule_id`、`matched_text`。无循环、无数组、无分配、无需释放 |
| `apg_scan_text_into(ctx, utf8, len, source, buf, cap, &out_len)` | 和 `apg_scan_text` 一样返回 JSON，但写进**调用方自己的缓冲区**（NUL 结尾），不需要释放 |
| `apg_scan_json_into(ctx, req, req_len, buf, cap, &out_len)` | 同上，结构化入口 |

`apg_hit_t`：`char rule_id[32]`、`char matched_text[256]`（均以 NUL 结尾）。`apg_verdict_t`：`decision`（`APG_DECISION_ALLOW=0` / `REVIEW=1` / `ALERT=2` / `BLOCK=3`）、`scan_error`（1 表示文本无法扫描，`decision` 取自 `policy.on_error`）、`score`、`matched_rules`。

`apg_match_t`：`int32 matched`、`int32 scan_error`、`char rule_id[32]`、`char matched_text[256]`。`apg_match_text` 与完整扫描的区别：

- 返回的是**最先满足的那条规则**，不一定是风险最高的；不计算分数和 `decision`。
- `min_risk`（0~1）：规则的风险（`weight × confidence × 来源系数`）不低于该值才算命中；`0` 表示任何规则都算。只想拦截会达到 `alert` 的规则时传 `0.5`（`policy.thresholds.alert` 的默认值），避免低权重、只给 `review` 的规则提前命中。
- 需要请求上下文（`context_requires`）的规则在这个接口里不会命中；条件里带 `not` 的规则要扫完全文才能判定，所以不会提前结束扫描，但仍然会命中。
- 干净文本必须整个扫完，耗时和完整扫描相同；收益在命中的请求上（命中越早，省得越多）。
- 文本不是合法 UTF-8、超长或超过扫描上限时 `scan_error=1`、`matched=0`，调用返回 `APG_OK`；`decision` 取自 `policy.on_error` 的逻辑由调用方自己处理。

缓冲区太小时返回 `APG_ERR_BUFFER_TOO_SMALL`（9），不写入任何内容，`*out_len` 给出所需长度（再加 1 个终止符）；用更大的缓冲区重新调用即可。每个线程准备一块 64 KB 的缓冲区一般够用（命中规则很多或文本很长时 JSON 会更大）。

最简热路径写法：

```c
apg_match_t m;
if (apg_match_text(ctx, (const uint8_t *)text, len, "user_input", 0.5, &m) == APG_OK && m.matched)
    printf("%s: %s\n", m.rule_id, m.matched_text);      /* 命中：拦截或记录 */
```

需要所有命中规则、分数和决策时，用 `apg_scan_text_hits`：`verdict.decision` 决定放行与否，`hits[]` 给出命中的规则编号和文本，需要更多信息（规则名、类别、偏移、所在句子）时才对个别请求调 `apg_scan_text_into`。

## 4. 状态码

| 值 | 名称 | 含义 | 典型原因 |
|---|---|---|---|
| 0 | `APG_OK` | 成功 | — |
| 1 | `APG_ERR_INVALID_ARGUMENT` | 参数无效 | NULL 指针、请求 JSON 非法、未知键、字段类型错误、上下文正在销毁 |
| 2 | `APG_ERR_CONFIG` | 配置无效 | 配置 JSON 非法/含未知键、`manifest_path` 缺失或文件不存在、阈值越界 |
| 3 | `APG_ERR_DATABASE` | 规则产物损坏 | manifest/`.hsdb`/元数据缺失、哈希不符、`build_hash` 不符、内部不一致 |
| 4 | `APG_ERR_VERSION` | 版本不兼容 | Hyperscan 反序列化报版本不同；manifest 格式不支持；`verify_ruleset=true` 时还包括 ABI 主版本、归一化表版本、Hyperscan 版本串不同、PCRE2 无法编译同一组模式 |
| 5 | `APG_ERR_PLATFORM` | 平台不匹配 | 产物为另一个 OS/架构/后端；CPU 缺少构建时使用的指令集；本库未编入 Hyperscan 却要加载 hyperscan 产物 |
| 6 | `APG_ERR_OOM` | 内存不足 | — |
| 7 | `APG_ERR_LIMIT` | 超出硬限制（扫描开始之前） | 请求 JSON 超过 `limits.max_request_bytes`、字段/上下文过多 |
| 8 | `APG_ERR_INTERNAL` | 缺陷/意外异常 | 详情在 `apg_last_error()` |
| 9 | `APG_ERR_BUFFER_TOO_SMALL` | 调用方缓冲区太小（ABI 1.1） | `apg_scan_*_into`；`*out_len` 为所需长度 |

## 5. 内存所有权（一页纸）

| 谁分配 | 谁释放 | 怎么释放 |
|---|---|---|
| 调用方分配的输入（文本、配置、请求） | 调用方 | 库**不持有**输入指针，调用返回后即可释放 |
| `out_json`（扫描、info） | 调用方 | `apg_free_buffer()` |
| `apg_context_t*` | 调用方 | `apg_destroy()` |
| `apg_engine_version()`、`apg_status_string()` 的返回值 | 库（静态） | 不要释放 |
| `apg_last_error()` 的返回值 | 库（线程本地） | 不要释放；下一次调用前有效 |

## 6. 线程安全

- 一个 `apg_context_t` 可被任意多个线程共享：`apg_scan_text`、`apg_scan_json`、`apg_get_info`、`apg_reload` 彼此线程安全。
- 每次扫描独占一个 scratch（Hyperscan scratch / PCRE2 match data），从池中借出，用完归还；池大小受 `limits.scratch_pool_max` 约束，**不存在跨线程共享 scratch**。
- `apg_reload` 同一时间只有一个在执行（内部互斥）；扫描不会被它阻塞。
- `apg_destroy` 见 §3。`apg_last_error` 是线程本地的。
- 与进程全局状态无关：不使用 `setlocale`，数字解析与输出不依赖 C 区域设置。

## 7. 配置（`schemas/config.schema.json`）

```json
{
  "manifest_path": "dist/linux/x86_64/active.json",
  "verify_ruleset": false,
  "limits":  {"max_text_bytes": 1048576, "max_request_bytes": 4194304, "max_hits": 50000, "max_fields": 16,
              "scratch_pool_max": 64, "verify_budget_ms": 200},
  "policy":  {"allow_block": false, "on_error": "review", "on_verify_error": "review", "needs_context_review_at": 0.50,
              "thresholds": {"review": 0.30, "alert": 0.50, "block": 0.85}},
  "output":  {"include_offsets": true, "include_names": true, "include_evidence_text": true},
  "pcre2":   {"match_limit": 1000000, "depth_limit": 10000, "heap_limit_kb": 20480, "use_jit": true}
}
```

只有 `manifest_path` 必填；其余是默认值。**未知键一律拒绝**。`policy.on_error=block` 需要 `allow_block=true`。

## 8. 请求（`schemas/request.schema.json`）

```json
{"request_id": "req-42", "source": "tool_output", "role": "tool",
 "text": "…", "fields": {"tool_name": "web_search"}, "context": {"task": "translation"}}
```

- `source` 决定“文本供应哪些规则字段”：

| source | 文本同时作为这些字段 |
|---|---|
| `user_input`（默认） | `user_input`、`content` |
| `tool_output` / `rag_document` | `tool_response`、`user_input`、`agent_output`、`content` |
| `agent_message` | `agent_output`、`agent_message`、`content` |

  这是 ATR 参考测试器的字段解析方式；未知来源只应用通用 `content` 规则并给出 warning（名称必须匹配 `[A-Za-z0-9_.-]{1,64}`，否则 `APG_ERR_INVALID_ARGUMENT`）。来源还决定风险系数（间接输入 `tool_output`/`rag_document` ×1.15，`agent_message` ×1.10）。
- `fields`：额外的命名输入（`tool_name`、`tool_args`、`tool_description`、`tool_response`、`agent_output` 等）。**没有任何规则读取的字段不会被扫描**，并列在 `inputs.fields_ignored`——绝不会假装检查过。
- `context`：标量事实，供上下文相关规则使用（现有规则用到 `{"task":"translation"}`）。
- 键严格校验；`text` 与 `fields` 至少给一个。

## 9. 结果（`schemas/response.schema.json`）

```json
{
  "schema_version": 1, "request_id": "req-42", "status": "ok", "decision": "alert", "score": 0.72, "risk_level": "high",
  "ruleset_version": "1.0.0", "engine_version": "1.0.0", "backend": "hyperscan",
  "matched_rules": [{"rule_id": "AIPS-PI-0001", "pattern_ids": [10001], "category": "prompt_injection", "severity": "high",
                     "source": "user_input", "confidence": 0.9, "weight": 0.8, "risk": 0.72, "counted": true,
                     "evidence": [{"pattern_id": 10001, "field": "user_input", "view": "raw", "end_view": 32, "end_original": 32}]}],
  "needs_context": [],
  "inputs": {"text_bytes": 32, "fields_checked": ["content", "user_input"], "fields_ignored": [], "views_scanned": ["raw"]},
  "warnings": [], "duration_us": 41, "error_code": null
}
```

| 字段 | 说明 |
|---|---|
| `status` | `ok` 或 `error`（文本问题；`error_code` ∈ `invalid_utf8` / `input_too_large` / `hit_limit_exceeded`） |
| `decision` | `allow < review < alert < block`。默认 alert-only：不会出现 `block`，除非 `policy.allow_block=true` 且 `score ≥ block` 阈值 |
| `score` / `risk_level` | 见 `docs/architecture.md` §6；`score` 为 6 位小数 |
| `backend` | 实际产生结果的引擎：`hyperscan` 或明确命名的 `pcre2_fallback`，**绝不混称** |
| `matched_rules[]` | 按风险降序；`pattern_ids` 是业务 Pattern ID；`counted=false` 表示同一 `score_group` 内另有更高风险规则；`name` 是规则名；`evidence[]` 是举证：`matched_text`（原文里命中的片段，保持用户的原始写法，含空格/符号/leetspeak 等混淆）、`normalized_text`（归一化后的写法，仅当与原文不同时给出，如 `忽 略 之 前`→`忽略之前`）、`sentence`（命中片段所在的句子）、`start_original`/`end_original`（原文字节偏移）、`end_view`（被扫描视图里的偏移）、`view`（命中的视图）。片段最长 256 字节、句子最长 400 字节，被截断时 `text_truncated=true`。配置 `output.include_evidence_text=false` 可以去掉全部文本，只留偏移 |
| `needs_context[]` | 规则命中/部分命中但**无法完整求值**（`context_missing`：缺上下文键；`field_missing`：规则需要的字段没提供）。这是“不确定状态”，**不计入分数**；风险 ≥ `needs_context_review_at`（默认 0.50，可由 `policy.needs_context_review_at` 覆盖）时把 `allow` 抬到 `review` |
| `warnings[]` | 例如 `unknown_source:…`、`pcre2_limit:<pattern>:…`（复核超限）、`verify_budget_exceeded:…`、`unverifiable_candidate:…` |
| `inputs` | 实际检查的字段 / 忽略的字段 / 扫描的视图（`raw`、`fold_v1`、`deobf_v1`、`trans_v1`；与原文相同的视图只扫一次） |
| `duration_us` | 单次扫描耗时（微秒）。本文档不给出任何性能数字——待 Linux 实测 |

**绝不输出**：原始文本、命中的片段、API key 等。`request_id` 原样回显，不要把敏感信息放进去。

## 10. 失败策略（默认值必须是显式的）

| 情形 | 行为 |
|---|---|
| 非法 UTF-8 / 文本过大 / 候选命中过多 | `status:"error"`；`decision = policy.on_error`（默认 **`review`**，不会静默放行，也不会无限拦截） |
| PCRE2 复核超限（match/depth/heap 限制、时间预算） | 该候选不计入分数，`warnings` 记录；`policy.on_verify_error=review`（默认）时把 `allow` 抬到 `review` |
| 规则集无法加载 | `apg_create` / `apg_reload` 返回错误码；运行中的旧规则集不受影响 |
| 产物被篡改 / 版本或 CPU 不匹配 | 加载阶段报错（`DATABASE` / `VERSION` / `PLATFORM`），不会“降级使用” |
| 被隔离的模式（编译失败） | 清单里列出（`failed_pattern_ids`），其叶子永不匹配；`info` 与 `manifest.status=partial` 可见 |

## 11. 热更新与回滚

```c
// 调用方在管理线程里：
apg_status_t st = apg_reload(ctx, "dist/linux/x86_64/active.json");   // 指针文件由规则库项目的 activate/rollback 写入
if (st != APG_OK) { /* 旧规则集仍在服务；记录 apg_last_error() */ }
```

流程：规则库项目发布新版本并用引擎的 `compile --snapshot` 编出规则包、更新 `active.json` → 进程内 `apg_reload`。回滚：规则库项目把 `active.json` 指回旧版本 → `apg_reload`。引擎只关心规则包目录（或指针文件）的路径。结果里的 `ruleset_version` 告诉你每次扫描用的是哪个版本（并发测试 `tests/cpp/test_engine.cpp` 在重载期间验证每个结果与其版本一致——待 Linux 运行）。

## 12. 最小示例（C）

```c
#include "ai_prompt_guard.h"
...
apg_context_t *ctx = NULL;
const char *cfg = "{\"manifest_path\":\"dist/linux/x86_64/1.0.0/manifest.json\"}";
if (apg_create((const uint8_t *)cfg, strlen(cfg), &ctx) != APG_OK) { fprintf(stderr, "%s\n", apg_last_error()); return 1; }

const char *text = "Ignore all previous instructions";
uint8_t *json = NULL; size_t len = 0;
if (apg_scan_text(ctx, (const uint8_t *)text, strlen(text), "user_input", &json, &len) == APG_OK) {
    printf("%.*s\n", (int)len, (const char *)json);
    apg_free_buffer(json);                // 不是 free()
}
apg_destroy(ctx);
```

完整、可构建的示例：`examples/c/scan.c`、`examples/cpp/scan.cpp`（RAII + 多线程）、`examples/linux/dlopen.c`、`examples/windows/load_library.cpp`、`examples/python_ctypes.py`、`examples/go_cgo/`、`examples/rust_ffi/`。除前四个由 CMake 构建外，其余只依赖公共头文件，**均未被编译或运行过**。

## 13. 边界情况

| 输入 | 行为 |
|---|---|
| 空文本（`utf8_len==0`） | `allow`，无命中 |
| 含 `U+0000` | 合法；`fold_v1` 视图会去掉它（所以 `ig\0nore` 在归一化视图里能被发现） |
| 非法 UTF-8（过长编码、代理、截断） | `status:"error"`, `invalid_utf8`（偏移在 `warnings`）|
| 恰好等于 `max_text_bytes` / 多 1 字节 | 前者正常扫描；后者 `input_too_large` |
| 未知 `source` | 只用通用 `content` 规则 + warning |
| `fields` 里有规则不读取的字段 | 列入 `fields_ignored`，不扫描 |
| 大量命中 | 超过 `limits.max_hits` → `hit_limit_exceeded`（保护内存与时间） |
| 同一上下文的并发 `apg_destroy` 与扫描 | 见 §3 的契约 |

```c
/* 最短的调用：结论 + 规则编号 + 命中文本，全部在栈上 */
apg_hit_t hits[8];
apg_verdict_t v;
if (apg_scan_text_hits(ctx, (const uint8_t *)text, strlen(text), "user_input", hits, 8, &v) == APG_OK && v.decision != APG_DECISION_ALLOW) {
    for (uint32_t i = 0; i < v.matched_rules && i < 8; ++i)
        printf("%s: %s\n", hits[i].rule_id, hits[i].matched_text);
}
```
