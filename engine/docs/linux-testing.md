# Linux 构建与测试

引擎项目自带的测试不需要规则库、数据库或 Python：**C++ 单元测试**（C ABI、热更新、并发、编译器、归一化黄金向量）。另有一组只用标准库的 Python 小测试（Schema 与静态检查）。真实规则包的行为（与参考引擎的差分、端到端发布流程）由规则库项目的测试负责，用的是你构建出的引擎。

## 1. 准备（一次性）

```bash
bash scripts/setup.sh --check     # 只检查工具：g++、cmake、make、pkg-config、ragel、boost 头文件、python3、git、curl、libpcre2-dev（含静态库）
bash scripts/setup.sh --install   # 缺什么就用系统包管理器装（需要 sudo），然后编译静态 Hyperscan → .deps/hyperscan
```

只用系统库、不想自己编译 Hyperscan 时可以跳过 `setup.sh`，装 libhyperscan-dev 与 libpcre2-dev 后用 `build.sh --system-libs`；完全没有 Hyperscan 用 `build.sh --no-hyperscan`。

## 2. 构建

```bash
bash scripts/build.sh                 # 自包含 .so → build/
bash scripts/build.sh --system-libs   # 动态链接系统库 → build-system/
bash scripts/build.sh --no-hyperscan  # pcre2_fallback → build-fallback/
bash scripts/build.sh --asan          # Debug + ASan/UBSan → build-asan/
```

## 3. 引擎自己的测试

```bash
bash scripts/test.sh                  # 或 --build build-asan
python3 tools/static_checks.py        # 头文件 / 实现 / 导出表 / JSON 契约的静态检查（不是编译）
```

## 4. 用真实规则包测试（在规则库项目里）

```bash
cd ../rules
bash scripts/compile.sh --cli ../engine/build/bin/ai-prompt-guard        # 导出快照 → 编译 → 登记 → 激活
bash scripts/test.sh --engine ../engine/build                            # 单元测试 + 端到端 + 与参考引擎的差分（--backend hyperscan|pcre2_fallback|both）
python3 tools/diff_hyperscan.py --lib ../engine/build/bin/libai_prompt_guard.so \
    --manifest dist/linux/x86_64/<版本>/manifest.json --version <版本>
```

端到端的步骤：编译 → 加载与校验 → 与参考引擎的差分（`tests/corpus` 与上游翻译数据集）→ 确定性 → CLI 契约 → 畸形请求 → 篡改检测 → 发布流程（新规则 → 发布 → 编译 → 激活 → 检测 → 回滚）→ 示例程序。

## 5. 基准（显式，从不自动运行）

```bash
bash scripts/bench.sh --manifest <规则包>/active.json --iterations 1500 --threads 1,2,4 --sizes 256,1024,4096,16384
```

只在空闲机器上测；数字必须与产生它的机器描述（输出旁的 `.host.txt`）放在一起。`examples/c/bench_live.c` 是逐秒输出的实时版本。
