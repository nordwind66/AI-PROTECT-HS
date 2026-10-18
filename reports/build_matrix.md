# 构建矩阵 / Build matrix

> “状态”只有三种：**已实测**（在开发机上运行并看到结果）、**待 Linux 执行**、**待 Windows 执行**。到目前为止，**没有任何 C/C++ 目标被编译过**。

## 1. 目标 × 平台

| 目标 | CMake 目标名 | Linux x86-64 | Windows x64 (MSVC) | 说明 |
|---|---|---|---|---|
| 动态库 | `ai_prompt_guard` | `bin/libai_prompt_guard.so`（待 Linux 执行） | `bin/Release/ai_prompt_guard.dll` + `lib/Release/ai_prompt_guard.lib`（待 Windows 执行） | 同一份源码：`APG_ENGINE_SOURCES`；`APG_BUILD_DLL` 定义导出宏；Linux 用 version script 只导出 `apg_*` |
| 静态库 | `apg_core_static` | `lib/libai_prompt_guard.a`（待 Linux 执行） | `lib/Release/ai_prompt_guard_static.lib`（待 Windows 执行） | 定义 `APG_STATIC`，供 CLI/测试链接 |
| 规则编译器 + SQLite 访问 | `apg_build` | 同上（待 Linux 执行） | 同上（待 Windows 执行） | 只在构建期使用，**不属于运行时库** |
| CLI | `ai-prompt-guard` | 待 Linux 执行 | 待 Windows 执行（`wmain`，MinGW 需 `-municode`） | compile / verify / info / scan / scan-batch / bench / versions |
| C++ 单元测试 | `apg_tests` | 待 Linux 执行 | 待 Windows 执行 | 自带微型测试框架，无外部依赖 |
| 示例 | `example_c_scan` `example_cpp_scan` `example_linux_dlopen` / `example_windows_load_library` | 待 Linux 执行 | 待 Windows 执行 | Go / Rust / Python 示例不由 CMake 构建 |

输出布局：`<build>/bin`（库、可执行文件、示例同目录）、`<build>/lib`（静态库、导入库）；多配置生成器追加 `/Release`。

## 2. 配置 × 依赖

| 预设 / 脚本参数 | Hyperscan | PCRE2 | SQLite | 后端 | 用途 |
|---|---|---|---|---|---|
| `linux-release` · `build.sh` | 必需 | 必需 | 必需（CLI/测试） | `hyperscan`（可同时编译 `pcre2_fallback` 产物） | 生产 |
| `linux-pcre2-fallback` · `build.sh --no-hyperscan` | 否 | 必需 | 必需 | 仅 `pcre2_fallback` | 无 Hyperscan 的机器；差分 oracle |
| `linux-debug-asan` · `build.sh --asan` | 必需 | 必需 | 必需 | `hyperscan` | ASan + UBSan |
| `windows-msvc` · `build.ps1` | 必需（风险高） | 必需 | 必需 | `hyperscan` | Windows 生产（待验证） |
| `windows-msvc-fallback` · `build.ps1 -NoHyperscan` | 否 | 必需 | 必需 | `pcre2_fallback` | Windows 保底 |

## 3. 编译器与选项

| 编译器 | 选项 |
|---|---|
| GCC/Clang | `-std=c++17`（`CXX_EXTENSIONS OFF`）、`-Wall -Wextra -Wno-unused-parameter`、`-fvisibility=hidden`、PIC；GCC < 9.1 链接 `stdc++fs` |
| MSVC | `/utf-8 /W4 /permissive- /Zc:__cplusplus /EHsc`；`_CRT_SECURE_NO_WARNINGS`、`NOMINMAX`；默认 `/MD`，`-DAPG_STATIC_RUNTIME=ON` → `/MT` |
| 共同 | 无 `-Werror`（首次在新编译器上构建不应被警告阻断；之后可收紧） |

## 3.1 已做的、不依赖编译器的检查（已实测）

| 检查 | 命令 | 结果 |
|---|---|---|
| 50 个 C/C++ 文件括号配对（词法感知）、`#include "…"` 可解析、头文件有 `#pragma once`、CMake 源文件清单与磁盘一致、公共头文件的每个函数在 `apg_api.cpp` 有定义、状态码/ABI 版本在头文件与 `common.h` 一致、C++ 加载器要求的 JSON 键在写出方存在 | `python tools/static_checks.py` | 无问题 — **这不是编译**，只能抓低级错误 |
| 人工逐文件审查（语法、类型、include、生命周期、并发） | — | 发现并修正了数个问题（见 `PROGRESS.md`）；无法保证没有遗漏 |

## 4. 依赖查找

`cmake/FindHyperscan.cmake`、`cmake/FindPCRE2.cmake`：按 `-DHYPERSCAN_ROOT` / `-DPCRE2_ROOT`（或同名环境变量）→ pkg-config → `CMAKE_PREFIX_PATH`/系统路径 的顺序查找；vcpkg 工具链同样适用。找不到时 CMake 报 `REQUIRED` 错误（不会下载、不会安装）。

## 5. 持续集成

`.github/workflows/ci.yml`（**未触发，未执行**）：`python-tooling`（两个 OS）、`linux-hyperscan`、`linux-pcre2-fallback`、`linux-sanitizers`、`windows-pcre2-fallback`、`windows-hyperscan`。没有 `continue-on-error`，依赖安装失败会让任务变红。
