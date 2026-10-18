# Windows 构建与调用（x64，MSVC）

> **状态：Windows 未编译验证。** 没有在任何 Windows 机器上编译过本项目的 C++ 代码，没有运行过 DLL。本文给出构建配置、脚本、示例与风险，**不得据此声称 DLL 已经能用**。任务书同时禁止在用户的 Windows 机器上安装工具，所以所有安装步骤只给出建议命令，由使用者自己决定在哪里执行。

## 1. 先看风险：Hyperscan 在 Windows 上是最不确定的一环

以下信息来自 2026-10 的网络检索摘要（链接见文末），**没有在本机或任何 Windows 机器上验证**：

| 事实（来源） | 含义 |
|---|---|
| Hyperscan 官方开发文档（5.4.1）把 Windows 支持描述为 *experimental*，列出 Intel C++ 编译器或 Visual Studio 2017 构建 | 官方不把 Windows 当作一等平台 |
| Intel 的 Windows 指南列出的前置依赖：CMake、VS 2017 Build Tools、Python 2.7、Ragel 6.9、Boost ≥ 1.57、PCRE 8.41、SQLite | **从源码自行构建 Hyperscan 很重**，且文档年代较老 |
| vcpkg 有 `hyperscan` 端口（5.4.2），支持表达式包含 windows-x64 / windows-x86，排除 arm 系列；2019 年最初的端口只提供静态库，之后有提交写明“允许构建为动态库”（#47786） | 最现实的获取方式是 `vcpkg install hyperscan:x64-windows`；静态/动态与本项目 DLL 的组合需要实测 |
| `python-hyperscan` 发布了捆绑 Hyperscan 5.4.2 的 Windows AMD64 wheel | 说明 Windows x64 能构建出可用的 Hyperscan（第三方证据） |
| 第三方（hyperscan-java）反馈 Windows 没有“fat runtime”，只能是 SSE3 基线 | 在 Windows 上性能上限可能低于 Linux，需要实测 |
| Vectorscan（Hyperscan 的可移植分支）：检索结果里没有关于 Windows/MSVC 的明确声明 | 不要假设它支持 MSVC |

**因此本项目的 Windows 策略是双轨的**：

1. **首选尝试** `hyperscan` 后端（vcpkg 或自编译），若成功则与 Linux 同构；
2. **保底** `pcre2_fallback` 后端（`-DAPG_WITH_HYPERSCAN=OFF` / `build.ps1 -NoHyperscan`）：功能与评分语义相同，使用 PCRE2 逐条执行，**明显更慢**，结果里的 `backend` 恒为 `pcre2_fallback`，绝不冒充 Hyperscan；
3. **生产建议**：如果宿主是 Windows 但性能和 Hyperscan 一致性重要，优先考虑 WSL2/Linux 容器里运行同一份 Linux 构建，再通过你自己的 IPC 调用。

## 2. 前置条件

| 需要 | 说明 |
|---|---|
| Visual Studio 2022（或 2019）/ Build Tools | 工作负载 “使用 C++ 的桌面开发”（含 MSVC x64、Windows SDK）。**不要求也不会被脚本安装** |
| CMake ≥ 3.16 | 随 VS 附带的也可以 |
| PCRE2（8-bit）、SQLite3 | CLI/编译器需要 SQLite；运行时库只需要 PCRE2（以及 Hyperscan，若使用） |
| Hyperscan（可选） | 见上一节 |
| Python 3.8+（可选） | 规则工具链与 e2e 测试 |

### 获取依赖（建议命令，脚本不会替你执行）

```powershell
# vcpkg 装到你选择的目录（不必在 C:）：
git clone https://github.com/microsoft/vcpkg D:\tools\vcpkg ; D:\tools\vcpkg\bootstrap-vcpkg.bat
D:\tools\vcpkg\vcpkg install pcre2:x64-windows sqlite3:x64-windows            # 保底方案所需
D:\tools\vcpkg\vcpkg install hyperscan:x64-windows                              # 若可用：生产方案
```

## 3. 构建

```powershell
# 只检查，不构建、不安装：
powershell -ExecutionPolicy Bypass -File scripts\windows\build.ps1 -CheckOnly -VcpkgToolchain D:\tools\vcpkg\scripts\buildsystems\vcpkg.cmake

# 带 Hyperscan（若依赖就绪）：
powershell -File scripts\windows\build.ps1 -VcpkgToolchain D:\tools\vcpkg\scripts\buildsystems\vcpkg.cmake

# 保底：显式 pcre2_fallback 后端
powershell -File scripts\windows\build.ps1 -NoHyperscan -VcpkgToolchain D:\tools\vcpkg\scripts\buildsystems\vcpkg.cmake

# 自己的前缀目录：-HyperscanRoot D:\libs\hyperscan -Pcre2Root D:\libs\pcre2 -Sqlite3Root D:\libs\sqlite
```

或直接用 CMake：`cmake --preset windows-msvc`（需要 `CMAKE_PREFIX_PATH`/vcpkg 工具链）、`cmake --build --preset windows-msvc`。

产物（`build\windows\bin\Release\`）：`ai_prompt_guard.dll`、`ai-prompt-guard.exe`、`apg_tests.exe`、`example_*.exe`；`build\windows\lib\Release\ai_prompt_guard.lib`（**DLL 的导入库**）和 `ai_prompt_guard_static.lib`（静态版，调用方需 `/DAPG_STATIC`）。DLL 与 EXE 在同一目录。

MSVC 选项：`/utf-8 /W4 /permissive- /EHsc`；默认 `/MD`（DLL 运行时），`-StaticRuntime` 改为 `/MT`。**源文件含 UTF-8 字面量（中文样例），必须 `/utf-8`**——CMake 已设置。构建路径最好不含非 ASCII 字符（测试把源码目录以编译定义传入）。

## 4. 测试

```powershell
powershell -File scripts\windows\test.ps1 -BuildDir build\windows-fallback -Backend pcre2_fallback    # 或 -Backend hyperscan / both
```

运行 C++ 单元测试（含 C ABI 与并发热更新）、Python 工具测试、端到端测试（编译→差分→tamper→release flow→示例，包括 `LoadLibrary` 示例）。工作在规则库的**副本**上。

## 5. 部署 DLL

- DLL 依赖：Hyperscan、PCRE2 的 DLL（若是动态链接）和 VC++ 运行库（`vcruntime140*.dll`、`msvcp140.dll`；或用 `/MT` 静态链接）。放在 `ai_prompt_guard.dll` 同目录，或用 `SetDllDirectoryW` / Python 的 `os.add_dll_directory` 指定。`LoadLibrary` 返回 126 通常是依赖 DLL 缺失。
- **内存所有权**：库返回的缓冲区必须用 `apg_free_buffer` 释放（调用方与 DLL 的 CRT 可以不同）。绝不能用调用方的 `free`。
- 不要混用 Debug 与 Release 的 DLL/EXE。
- 规则产物必须**在 Windows 上编译**（`ai-prompt-guard compile` 的输出目录 `dist\windows\x86_64\<version>\`）；Linux 上的 `.hsdb` 不能拷过来，manifest 里的 `target.os` 也会让加载失败。
- 路径一律 UTF-8：CLI 使用 `wmain` 并转换；库内部用 `std::filesystem::u8path`。传给 `apg_create` 的 `manifest_path` 是 UTF-8 JSON 字符串（反斜杠需转义）。

## 6. 从其他程序调用

| 方式 | 示例 | 要点 |
|---|---|---|
| C / C++（链接导入库） | `examples/c/scan.c`、`examples/cpp/scan.cpp` | `cl /utf-8 scan.c /I include ai_prompt_guard.lib`，DLL 与 EXE 同目录 |
| `LoadLibrary` / `GetProcAddress` | `examples/windows/load_library.cpp` | 函数指针类型使用头文件的 `APG_CALL`（`__cdecl`）；命令行参数用 `wmain` 转 UTF-8 |
| Python | `examples/python_ctypes.py` | `ctypes.CDLL`（不是 `WinDLL`；x64 只有一种调用约定）；`os.add_dll_directory` |
| Go | `examples/go_cgo/`（cgo 需要 MinGW-w64，且需要与之兼容的导入库） | 用 MSVC 构建的 DLL 更省事的方式是 `golang.org/x/sys/windows`（`LoadLibrary`/`GetProcAddress`），ABI 相同 |
| Rust | `examples/rust_ffi/`（MSVC 目标链接 `ai_prompt_guard.lib`） | 设置 `AI_PROMPT_GUARD_LIB_DIR` |
| C# | P/Invoke：`[DllImport("ai_prompt_guard", CallingConvention = CallingConvention.Cdecl)]`，字节数组 + 显式长度，结果用 `Marshal.Copy` 后调用 `apg_free_buffer` | 未提供示例项目 |

## 7. 未验证项与已知风险（汇总）

1. 全部 C++ 代码未在 MSVC 下编译（可能有 MSVC 专有的警告/错误：`/W4`、`std::filesystem`、`gmtime_s`、`wmain`）。
2. Hyperscan 在 Windows 上的可获得性、静态/动态链接组合、构建选项、CPU 特性派发均未验证（见 §1）。
3. `thread_local std::string`（`apg_last_error`）在 DLL 中的行为依赖运行时版本（现代 MSVC 支持；未验证）。
4. 不同 CRT 之间的内存所有权靠 `apg_free_buffer` 约定保证，需要用“调用方 `/MT` + DLL `/MD`”组合实测一次。
5. 控制台编码：CLI 设置 `SetConsoleOutputCP(CP_UTF8)`；通过管道读取时由调用方负责按 UTF-8 解码。
6. 没有 Windows CI 的运行记录（`.github/workflows/ci.yml` 已提供，**未触发**）。

## 8. Windows 验收清单

- [ ] `build.ps1 -NoHyperscan` 成功；`test.ps1 -Backend pcre2_fallback` 全部通过
- [ ] `LoadLibrary` 示例、C 示例、C++ 示例、Python ctypes 示例返回相同的检测结果
- [ ] 调用方 `/MT`、DLL `/MD` 组合下 `apg_free_buffer` 无崩溃
- [ ] （若有 Hyperscan）`build.ps1` 成功，`test.ps1 -Backend both` 通过；记录 Hyperscan 来源（vcpkg 版本/自编译）与是否 SSE3-only
- [ ] 结果和日志回填 `reports/validation_matrix.md`

## 来源（检索于 2026-10；摘要，未逐页核实全文）

- vcpkg `hyperscan` 端口：<https://vcpkg.io/en/package/hyperscan.html>
- Intel：Get Started with Hyperscan on Windows：<https://www.intel.com/content/www/us/en/developer/articles/guide/get-started-with-hyperscan-on-windows.html>
- Hyperscan 开发者文档 Getting Started（Windows 为 experimental）：<https://intel.github.io/hyperscan/dev-reference/getting_started.html>
- Hyperscan Issue #105（Windows 动态库）：<https://github.com/intel/hyperscan/issues/105>
- python-hyperscan（Windows wheel）：<https://python-hyperscan.readthedocs.io/>
- Vectorscan：<https://github.com/VectorCamp/vectorscan>
