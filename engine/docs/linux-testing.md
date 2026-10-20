# Linux 构建与测试

引擎项目自带的测试不需要规则库、数据库或 Python：**C++ 单元测试**（C ABI、热更新、并发、编译器、归一化黄金向量）。另有一组只用标准库的 Python 小测试（Schema 与静态检查）。真实规则包的行为（与参考引擎的差分、端到端发布流程）由规则库项目的测试负责，用的是你构建出的引擎。

## 1. 依赖

```bash
bash scripts/linux/setup_deps.sh            # 只检查并给出建议命令（--install 才执行包管理器命令）
```

需要 g++ ≥ 8、CMake ≥ 3.16、pkg-config、**libhyperscan-dev（5.x）**、libpcre2-dev（≥ 10.30）。没有 Hyperscan 包时从 <https://github.com/intel/hyperscan> 自行构建，或先用 `--no-hyperscan` 验证其余部分（显式的 `pcre2_fallback` 后端）。

## 2. 构建

```bash
bash scripts/linux/build.sh                    # Release；build/linux/bin 与 build/linux/lib
bash scripts/linux/build.sh --static --hyperscan-root /opt/hs-static   # 自包含的 .so（见 embedding.md）
bash scripts/linux/build.sh --no-hyperscan     # 没有 Hyperscan：build/linux-fallback
bash scripts/linux/build.sh --asan             # Debug + ASan/UBSan：build/linux-asan
```

## 3. 引擎自己的测试

```bash
bash scripts/linux/test.sh --build-dir build/linux        # CTest: cpp_unit
python3 -X utf8 -m unittest discover -s tests/python      # Schema 与静态检查（可选，只需 Python 3 标准库）
python3 tools/static_checks.py                            # 头文件 / 实现 / 导出表 / JSON 契约的静态检查（不是编译）
```

## 4. 用真实规则包测试（在规则库项目里）

```bash
cd ../rules
bash scripts/linux/init_rules.sh --cli ../engine/build/linux/bin/ai-prompt-guard      # 导出快照 → 编译 → 登记 → 激活
python3 -X utf8 tests/e2e/run_e2e.py --cli ../engine/build/linux/bin/ai-prompt-guard --workdir /tmp/e2e --db /tmp/rules.db \
    --backend hyperscan --lib ../engine/build/linux/bin/libai_prompt_guard.so --examples-dir ../engine/build/linux/bin --clean
python3 tools/diff_hyperscan.py --lib ../engine/build/linux/bin/libai_prompt_guard.so \
    --manifest dist/linux/x86_64/<版本>/manifest.json --version <版本>
```

e2e 的步骤：编译 → 加载与校验 → 与参考引擎的差分（`tests/corpus` 与上游翻译数据集）→ 确定性 → CLI 契约 → 畸形请求 → 篡改检测 → 发布流程（新规则 → 发布 → 编译 → 激活 → 检测 → 回滚）→ 示例程序。

## 5. 基准（显式，从不自动运行）

```bash
bash scripts/linux/bench.sh --run --build-dir build/linux-static --manifest <规则包>/manifest.json \
     --iterations 1500 --threads 1,2,4 --sizes 256,1024,4096,16384 --out reports/bench_<主机>.json
```

只在空闲机器上测；数字必须与产生它的机器描述（输出旁的 `.host.txt`）放在一起。`examples/c/bench_live.c` 是逐秒输出的实时版本。
