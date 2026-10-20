# 性能：测试计划（**待 Linux 实测，本文没有任何实测数据**）

任务书禁止在用户的电脑上做性能测试，也禁止捏造 P95、吞吐或通过率。所以这里只有**计划、方法与记录模板**；每一个“结果”单元格都是“待 Linux 实测”。

## 1. 要回答的问题

1. 编译：把已发布快照编译成 `.hsdb` 要多久、多大？预过滤模式占多少？
2. 加载：`apg_create` / `apg_reload` 要多久、峰值与稳态内存多少？
3. 扫描：不同文本长度下的延迟分布（P50/P95/P99）与吞吐？无命中 / 低命中 / 高命中的差异？
4. 开销拆分：归一化（`fold_v1`/`trans_v1`）与 PCRE2 复核各占多少？
5. 扩展性：1/2/4/8… 线程的吞吐伸缩？scratch 池是否成为瓶颈？
6. 库规模：SQLite 导入、发布耗时，数据库、快照、`.hsdb` 体积。
7. 对比：Hyperscan 后端 vs 显式的 `pcre2_fallback` 后端（说明为什么 Hyperscan 是主引擎）。

## 2. 方法

- **工具**：`ai-prompt-guard bench`（经公共 C ABI 扫描，含 JSON 结果构建；不是内部函数的微基准）。`scripts/linux/bench.sh --run` 是**唯一入口**，必须显式给 `--run`（或 `APG_RUN_BENCH=1`）；构建、测试、安装、CI 都不会触发它。
- **语料**：`tests/corpus/*.jsonl`（人工语料）按 256 B、1 KiB、4 KiB、16 KiB、64 KiB 拼接成样本（不切断 UTF-8）。三种混合：
  - `nohit_filler`：与规则无关的普通英文句子 —— 无命中；
  - `lowhit_normal_text`：正常语料 —— 低命中；
  - `highhit_attack_text`：攻击语料拼接 —— 高命中。
  每个混合先做一次不计时的预扫描，**报告实际被命中的样本比例与平均命中规则数**，防止“声称高命中而实际没命中”。
- **指标**：每次扫描的延迟（µs）→ P50/P95/P99；每秒扫描数；MB/s；失败数；`apg_create` 时间与 RSS 前后；线程数 1,2,4,8…（不超过物理核数的若干倍）。
- **环境记录**（与数字一起保存，缺一不可）：`lscpu`、内存、内核、CPU governor、编译器与选项、Hyperscan/PCRE2/SQLite 版本、规则集版本与快照 SHA-256、`cpu-target`、是否同时运行了其他负载。
- **纪律**：空闲机器；先预热；固定 CPU governor 为 performance；同一规则集；多次运行取分布，不挑最好的一次；不用笔记本电池供电或共享的嘈杂 CI 机器。
- **编译/体积**：`bench.sh --run --compile-timing`（拷贝数据库副本→`compile`→记录秒数与目录/数据库体积）。导入/发布耗时：`/usr/bin/time -v python3 tools/build_rules_db.py --fresh --db /tmp/x.db --no-reports`。

## 3. 结果模板（全部待填）

### 编译与体积

| 项 | 值 |
|---|---|
| `compile` 耗时（generic / host） | 一次观察（16 个工作线程，generic，**不是基准**）：旧默认时限 83.4–85.9 s（逐条筛选约 52 s、分片编译约 30 s）；两级时限（15 s / 60 s）后 48.7–50.1 s（逐条筛选约 28 s、分片编译约 20 s）。日志见 `reports/logs/`；其余待规范的 Linux 实测。需同时记录 `--jobs`、`--shards`、CPU 线程数、`build_report.json` 的 `build_stats` 和进度输出；耗时与并行度强相关（新版 `compile` 默认用所有 CPU 线程，第一次实测中旧的单线程版本数小时未完成，见 `PROGRESS.md` §9） |
| `.hsdb` 总大小、各 profile 大小、分片数 | 一次观察（不是基准）：19 个文件（fold_v1 16 + trans_v1 3），旧默认时限约 91 MiB（其中两个只含 1 个模式的分片各 3.3 MiB），两级时限后约 85 MiB。见 `reports/logs/` |
| 被降级为 prefilter / 放宽重复的模式数（`downgraded_to_prefilter` / `relaxed_repeats`） | 待 Linux 实测（影响运行时的 PCRE2 复核开销） |
| SQLite 文件大小 | 13.9 MB（事实，非测量；会随规则变化） |
| 发布快照大小 | 1 679 307 字节（事实） |
| 导入+发布耗时（Python 工具链） | 待 Linux 实测（开发机 Windows 上一次构建约 17–20 s，仅作旁证，不是验收数据） |

### 扫描（每个单元格：P50 / P95 / P99 µs · 扫描/秒 · MB/s）

| 文本长度 | 无命中 | 低命中 | 高命中 |
|---|---|---|---|
| 256 B | 待 Linux 实测 | 待 Linux 实测 | 待 Linux 实测 |
| 1 KiB | 待 Linux 实测 | 待 Linux 实测 | 待 Linux 实测 |
| 4 KiB | 待 Linux 实测 | 待 Linux 实测 | 待 Linux 实测 |
| 16 KiB | 待 Linux 实测 | 待 Linux 实测 | 待 Linux 实测 |
| 64 KiB | 待 Linux 实测 | 待 Linux 实测 | 待 Linux 实测 |

### 多线程伸缩（4 KiB 低命中）

| 线程数 | 1 | 2 | 4 | 8 |
|---|---|---|---|---|
| 扫描/秒 | 待 Linux 实测 | 待 Linux 实测 | 待 Linux 实测 | 待 Linux 实测 |

### 加载与内存

| 项 | 值 |
|---|---|
| `apg_create` 耗时 | 待 Linux 实测 |
| 加载前后 RSS | 待 Linux 实测 |
| `apg_reload` 期间扫描延迟变化 | 待 Linux 实测 |

### 开销拆分（需要在引擎里加计时钩子或用 `perf`）

| 阶段 | 占比 |
|---|---|
| 归一化（`fold_v1` / `trans_v1`） | 待 Linux 实测 |
| Hyperscan 扫描 | 待 Linux 实测 |
| PCRE2 复核 | 待 Linux 实测 |
| 评分与 JSON 构建 | 待 Linux 实测 |

## 4. 设计层面已知的性能风险（待实测验证，不是结论）

- 复核用的预过滤模式只有 16 个，且仅在 Hyperscan 报告候选后才执行；但某些候选可能很宽（`.*` 之类），PCRE2 限额（match/depth/heap）与时间预算是兜底。
- `fold_v1` 视图在含非 ASCII 字符（尤其中文）时需要逐字符归一化并复制文本；ASCII 文本不复制。
- 每次调用仍分配结果字符串等小对象；没有做内存池优化。
- scratch 池大小默认 64；线程数超过池容量时多余的 scratch 在用完后销毁（会增加分配）。
- Windows 上 Hyperscan 可能只有 SSE3 基线（第三方信息，未验证）。
- 更大的 `max_text_bytes` 会线性增加归一化与扫描耗时；对长文本建议调用前分块。
