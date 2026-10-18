# 集成指南（嵌入到你的程序）

本项目只提供**进程内的函数 API / CLI**，没有 HTTP 服务、没有 APISIX/网关适配、没有 Web UI（任务书明确不做）。把它嵌入你自己的程序，或在你自己的服务里包一层。
接口契约见 `docs/c-api.md`，规则维护见 `docs/rule-maintenance.md`。以下建议基于代码与设计，**未经真实流量验证**。

## 1. 部署布局

```text
your-app/
├── bin/your-app(.exe)
├── lib/libai_prompt_guard.so  | ai_prompt_guard.dll (+ Hyperscan / PCRE2 / VC 运行库的 DLL)
└── rules/
    ├── 1.0.0/{manifest.json, rules.fold_v1.*.hsdb, rules.trans_v1.*.hsdb, ruleset.meta.json, build_report.json}
    │         (大规则集会把每个 profile 拆成 rules.<profile>.01.hsdb、.02.hsdb … 多个分片；全部由 manifest 登记并校验，运行时依次扫描)
    └── active.json                     # {"kind":"apg-active-pointer", "manifest":"1.0.0/manifest.json", "manifest_sha256":…}
```

- `rules/` 来自 `ai-prompt-guard compile` 在**目标机器**上的输出（`dist/<os>/<arch>/…`）。**不要**把一台机器编译的 `.hsdb` 拷到另一台（Hyperscan 版本 / CPU 特性 / OS 不同会被加载阶段拒绝）。要更新规则：在目标机器上用 SQLite 里已发布的版本重新编译（`scripts/linux/init_rules.sh`）。
- 运行时**不需要** SQLite、Python、规则库文件。
- **宿主进程自带较旧的 libstdc++ 时**（典型：conda / venv 的 Python 通过 ctypes 加载）：`dlopen` 报错 “GLIBCXX_3.4.xx not found (required by libai_prompt_guard.so)”，因为宿主先加载了自己的旧 libstdc++。这是环境冲突，不是库的缺陷（Linux 第一次实测遇到过，见 `reports/PROGRESS.md` §10）。处理办法按推荐顺序：① 用系统自带的 Python 或不在 conda 环境里的宿主；② 启动时 `LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libstdc++.so.6`（路径用 `ldconfig -p | grep libstdc++` 查）；③ 在 conda 里升级 `libstdcxx-ng`（会改动环境）。Hyperscan 的 `libhs` 也依赖系统的 libstdc++，所以只给本库静态链接 libstdc++ 解决不了这个问题。
- 应用启动时 `manifest_path` 指向 `rules/active.json`，这样升级/回滚只需要改指针并 `apg_reload`。

## 2. 选择后端

| 后端 | 何时用 | 注意 |
|---|---|---|
| `hyperscan`（生产） | Linux x86-64；有 Hyperscan 5.x | 数据库与 Hyperscan 版本、CPU 绑定；`--cpu-target generic` 更可移植 |
| `pcre2_fallback`（显式） | 没有 Hyperscan（例如 Windows 暂时拿不到可用的 Hyperscan 构建）；差分测试 oracle | 逐条执行，**明显更慢**；每个结果里 `backend` 都是 `pcre2_fallback` |

库在构建时用 `-DAPG_WITH_HYPERSCAN=OFF` 就不再链接 Hyperscan；此时只能加载 `pcre2_fallback` 产物。

## 3. 推荐用法

```c
// 进程启动：创建一次，全进程共享（线程安全）
apg_create(cfg, len, &g_ctx);

// 每个请求：
apg_scan_json(g_ctx, request_json, request_len, &out, &out_len);   // 或 apg_scan_text
// 解析 out（decision / matched_rules / needs_context），然后 apg_free_buffer(out)
```

1. **一次创建，多线程共享。** 不要每个请求创建/销毁上下文——加载包含哈希校验与数据库反序列化。
2. **如实标注来源。** 用户输入 → `user_input`；工具/MCP 返回、网页、检索到的文档 → `tool_output` / `rag_document`（间接注入风险更高，系数 ×1.15，字段映射也不同）；其他 Agent 的消息 → `agent_message`。
3. **声明场景上下文。** 翻译/改写类应用必须传 `{"context": {"task": "translation"}}`，否则“仅翻译场景”的规则不会计入分数，只出现在 `needs_context` 里，并在其风险达到 `needs_context_review_at`（默认 0.50）时把 `allow` 抬到 `review`——引擎不假装条件已经成立，也不假装没看见。这是集成方的责任：翻译场景请传上下文；**没有翻译类场景**的应用可以设置 `policy.needs_context_review_at: 1.0` 关闭这类 `review`（它们对普通中文指令句偶有噪声，见 `reports/false_positive.md`），发现仍可在 `needs_context[]` 里看到。
4. **按 `decision` 处理，而不是 `matched_rules` 非空。** 默认只有 `allow / review / alert`：
   - `alert`：高置信度命中，建议记录并按业务策略处理（提示、降权、转人工、拒绝由**你的**策略决定）；
   - `review`：弱信号或不确定（也包括文本无法扫描时的 `status:"error"`），建议转人工/二次审查或限制敏感操作；
   - `block` 只有在你显式设置 `policy.allow_block=true` 并经过自己数据的误报评估之后才使用。
5. **不要把结果当作可信的“安全证明”。** `allow` 只表示“没有已知的正则信号”。改写、冷门语言、编码绕过、语义层攻击都可能漏掉（`reports/detection_eval.md` 列出了已知缺口）。把它作为纵深防御的一层。
6. **日志脱敏。** 结果本身不含原文；你的日志也不要写完整 prompt、API key。`request_id` 原样回显，不要放敏感信息。
7. **限额。** 按业务设置 `limits.max_text_bytes`（默认 1 MiB），超过得到 `input_too_large`（`review`）。很长的文档在调用前先分块；每块独立判断，再自行合并。
8. **失败策略显式化。** `policy.on_error`（文本无法扫描）与 `on_verify_error`（PCRE2 复核超限）默认都是 `review`；如果你的业务要 fail-open，请显式配置 `allow`，并把这一决定写进你的运行手册。
9. **热更新。** 管理线程调用 `apg_reload`；失败只记录日志，旧规则继续服务。重载前确认新目录已通过 `ai-prompt-guard verify --manifest …`。
10. **销毁顺序。** 先停止/汇合所有扫描线程，再 `apg_destroy`。

## 3.1 Windows 与 Linux 的调用方式（逐一说明）

> 以下代码都在 `examples/` 里完整给出；**均未被编译或运行过**（待 Windows / Linux 实测）。

### Windows C/C++：方式一 —— 编译时链接 `.h + .lib`，运行时加载 `.dll`

```bat
cl /utf-8 /std:c++17 /EHsc app.cpp /I include ai_prompt_guard.lib        :: 编译 + 链接导入库
:: 运行时 ai_prompt_guard.dll 必须能被找到：
::   1. 与 app.exe 在同一目录（最简单、最可靠）；或
::   2. 在程序启动时调用 SetDllDirectoryW(L"D:\\path\\to\\dll") / AddDllDirectory；或
::   3. 目录在 PATH 中（不推荐：全局副作用）
::   同样，Hyperscan / PCRE2 / VC++ 运行库的 DLL 也要在这些位置之一
```

- 头文件的 `APG_API` 在使用方展开为 `__declspec(dllimport)`，`APG_CALL` 为 `__cdecl`；**不要**在使用方定义 `APG_BUILD_DLL`。链接静态版（`ai_prompt_guard_static.lib`）时定义 `APG_STATIC`。
- 结果缓冲区必须用 `apg_free_buffer` 释放（不要用调用方 CRT 的 `free`）。
- 程序启动时检查 `(apg_abi_version() >> 16) == APG_ABI_VERSION_MAJOR`。完整代码：`examples/c/scan.c`、`examples/cpp/scan.cpp`（RAII 封装）。

### Windows C/C++：方式二 —— `LoadLibraryW` + `GetProcAddress`（编译时不依赖导入库）

```cpp
HMODULE lib = LoadLibraryW(L"D:\\app\\ai_prompt_guard.dll");            // 失败时 GetLastError()==126 通常是依赖 DLL 缺失
typedef apg_status_t(APG_CALL* pfn_create)(const uint8_t*, size_t, apg_context_t**);
pfn_create create = (pfn_create)GetProcAddress(lib, "apg_create");      // 函数名即 C 名字，无修饰
...
FreeLibrary(lib);                                                       // 在所有 context 销毁、所有缓冲区释放之后
```

- 路径在程序里用 UTF-8，调用 Windows API 时用 `MultiByteToWideChar(CP_UTF8, …)` 转 UTF-16；库本身只接收 UTF-8（`wmain` 取命令行、`std::ifstream(wstring)` 读文件）。
- 需要同目录的依赖 DLL 时，先 `SetDllDirectoryW(目录)` 再 `LoadLibraryW`。
- 完整代码：`examples/windows/load_library.cpp`（检查 ABI、创建、扫描、释放、销毁、卸载）。

### Linux：方式一 —— 链接 `-lai_prompt_guard`

```bash
cc scan.c -I include -L build/linux/bin -lai_prompt_guard -o scan
LD_LIBRARY_PATH=build/linux/bin ./scan dist/linux/x86_64/active.json "ignore all previous instructions"
# 部署时更好的做法：链接时加 -Wl,-rpath,'$ORIGIN/../lib'，或把库安装到系统库目录并 ldconfig
```

### Linux：方式二 —— `dlopen` / `dlsym`

```c
void *lib = dlopen("./libai_prompt_guard.so", RTLD_NOW | RTLD_LOCAL);
*(void **)(&create) = dlsym(lib, "apg_create");
...
dlclose(lib);                       // 在所有 context 销毁、所有缓冲区释放之后
```

完整代码：`examples/linux/dlopen.c`（旧版 glibc 链接加 `-ldl`）。

## 4. 各语言要点

| 语言 | 要点 | 示例（均未编译/运行过） |
|---|---|---|
| C | 直接包含头文件；`apg_free_buffer` 释放结果 | `examples/c/scan.c`（CMake 构建） |
| C++ | RAII 包装；不要在 ABI 边界传 `std::string` | `examples/cpp/scan.cpp`（CMake 构建） |
| Python | `ctypes.CDLL`（两个平台都是 cdecl）；Windows 先 `os.add_dll_directory`；用 `ctypes.string_at` 拷贝后 `apg_free_buffer` | `examples/python_ctypes.py` |
| Go | cgo；Go 内存可传给 C（库不保存指针）；结果 `C.GoBytes` 拷贝后 `apg_free_buffer`（不是 `C.free`） | `examples/go_cgo/main.go` |
| Rust | `extern "C"`；自行保证不在销毁后使用句柄；`Guard` 手动 `unsafe impl Send/Sync` | `examples/rust_ffi/` |
| 其他（C# / Java / Node） | 任何能调用 C ABI（cdecl）的 FFI 均可：P/Invoke `CallingConvention.Cdecl`、JNA、node-ffi-napi；注意 UTF-8 与显式长度 | — |

## 5. 容量与性能

本仓库**不含任何性能数字**（任务书禁止在本机做性能测试，也不允许捏造跑分）。设计上的性能特征：请求路径不访问 SQLite、不动态编译、不逐条规则扫描（每个 profile×视图一次批量扫描）、Hyperscan/PCRE2 的 scratch 与 match data 池化复用（不是每次扫描分配）、ASCII 文本的 `fold_v1` 视图与原文相同时不拷贝。每次调用仍会分配结果字符串和若干小向量（未做内存池优化）。实测计划见 `reports/performance.md`，执行入口 `scripts/linux/bench.sh --run`。

## 6. 与现有系统集成时的几点提醒

- 本项目**不是**网关插件。若要放到网关里，请在你的网关插件里调用本库；这不在本项目范围内。
- 同一进程里加载多份不同版本的库（例如宿主与插件各带一份）时，符号只导出 `apg_*`，但 Hyperscan/PCRE2 的版本冲突仍然可能发生——统一依赖版本。
- Windows：见 `docs/windows-build.md`（特别是 Hyperscan 的风险说明）。
