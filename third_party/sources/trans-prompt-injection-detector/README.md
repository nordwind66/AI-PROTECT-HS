# 翻译提示注入检测器

> Translation Prompt Injection Detector —— 基于规则正则 + LLM 的混合提示注入检测工具

本项目面向机器翻译场景，实现了一个提示注入（Prompt Injection）检测系统。通过正则规则匹配 + 加权评分机制作为快速筛查，可选结合 LLM 语义检测处理模糊边界案例，识别试图劫持翻译系统的对抗性输入。支持中英双语及中英混合的隐蔽注入攻击检测。

## 功能特性

- **规则驱动检测**：11 大类共 113 条正则模式，覆盖中英文常见提示注入攻击手法
- **中英双语支持**：检测中文、英文及中英混合（语码转换）的注入攻击
- **Unicode 混淆防御**：全角/半角规范化、同形字映射、零宽字符移除，应对编码层绕过
- **加权评分机制**：不同危险等级规则分配不同权重（1-3 分），综合判定风险
- **三级风险评级**：Low / Medium / High，对应无攻击、疑似攻击、确认攻击
- **LLM 混合检测**（可选）：正则初筛 + LLM 语义确认，兼顾速度与准确性
- **完整评估体系**：Accuracy / Precision / Recall / F1 / 混淆矩阵 / 攻击类型检出率
- **详细检测报告**：JSON + Markdown 双格式评估报告 + 可视化图表
- **规则优化器**：自动分析 FP/FN、规则重叠、词边界建议、权重调优
- **Web 可视化界面**：Flask 前端，浏览器内切换检测方法、粘贴文本、查看评分与证据链

## 项目结构

```
trans-prompt-injection-detector/
├── prompt_injection_detector.py          # 主检测程序（正则引擎 + 预处理）
├── evaluator.py                          # 评估模块（指标计算 + 报告生成）
├── llm_detector.py                       # LLM 检测器 + 混合检测逻辑
├── config.py                             # 配置管理（环境变量）
├── rule_optimizer.py                     # 规则优化分析器
├── generate_dataset.py                   # 数据集扩展生成脚本
├── app.py                                 # Flask Web 界面
├── templates/                             # 前端页面模板
│   └── index.html
├── translation_pia_dataset_shuffled.jsonl # 原数据集（1000条英文标注样本）
├── cn_mixed_dataset.jsonl                 # 新增中文/混合样本（375条）
├── full_dataset.jsonl                     # 合并全量数据集（1375条）
├── tests/                                # 单元测试
│   ├── test_preprocessing.py
│   ├── test_detection.py
│   ├── test_cn_detection.py              # 中文检测规则测试
│   └── test_evaluation.py
├── requirements.txt
├── pyproject.toml
├── .env.example
└── README.md
```

## 快速开始

### 环境要求

- Python 3.8+
- （可选）matplotlib —— 用于生成图表，未安装时自动跳过

### 安装

```bash
pip install -r requirements.txt
```

### 基本使用

```bash
# 默认运行（正则检测）
python prompt_injection_detector.py

# 指定数据文件和输出目录
python prompt_injection_detector.py --data my_data.jsonl --output ./results

# 使用全量中英混合数据集
python prompt_injection_detector.py --data full_dataset.jsonl

# 运行评估（对比 ground truth 计算指标）
python prompt_injection_detector.py --eval

# LLM 检测模式（需配置 API key，可选 --provider 指定后端）
python prompt_injection_detector.py --method llm --provider deepseek

# 混合模式（正则 + LLM）
python prompt_injection_detector.py --method hybrid --provider ollama --eval

# 自定义阈值
python prompt_injection_detector.py --threshold 5
```

### 数据集扩展

```bash
# 生成中文/中英混合数据集
python generate_dataset.py

# 输出文件：
#   cn_mixed_dataset.jsonl  — 375 条新增样本
#   full_dataset.jsonl      — 1375 条合并全量样本
```

### Web 界面

```bash
python app.py
# 浏览器打开 http://127.0.0.1:5000
```

三种检测方法可选，Regex 模式无需任何配置，打开就能用。LLM 和 Hybrid 模式需要在界面的设置面板里填入 API Key 和选择 Provider，也可按需填写自定义 Endpoint 和 Model 名称。密钥存浏览器本地不会上传。粘贴文本点击检测，结果会展示风险等级、评分、命中规则和匹配到的证据片段。支持中文和混合语言输入。

API 提供 `GET /api/health` 健康检查端点。

> 想给非技术同学演示的话，直接让他们打开网页用 Regex 模式就行，什么都不用配。

### LLM 配置

**方式一：`.env` 文件（推荐）**

```bash
cp .env.example .env
# 编辑 .env，填入 API Key 和 provider
```

`.env` 示例：
```bash
DETECTOR_LLM_API_KEY="sk-your-key"
DETECTOR_LLM_PROVIDER="deepseek"        # 见下方支持列表
# DETECTOR_LLM_MODEL 和 DETECTOR_LLM_ENDPOINT 会自动填充，无需手动设置
```

**方式二：环境变量**

```bash
export DETECTOR_LLM_API_KEY="your-api-key"
export DETECTOR_LLM_PROVIDER="deepseek"
```

**方式三：CLI 参数**

```bash
python prompt_injection_detector.py --method llm --provider ollama --model llama3.2
```

**支持的 Provider**

| Provider | 默认 Endpoint | 默认 Model | 需要 API Key |
|----------|--------------|-----------|:---:|
| `anthropic` | api.anthropic.com/v1/messages | claude-haiku-4-5-20251001 | 是 |
| `openai` | api.openai.com/v1 | gpt-4o-mini | 是 |
| `deepseek` | api.deepseek.com/v1 | deepseek-chat | 是 |
| `zhipu` | open.bigmodel.cn/api/paas/v4 | glm-4-flash | 是 |
| `qwen` | dashscope.aliyuncs.com/compatible-mode/v1 | qwen-turbo | 是 |
| `groq` | api.groq.com/openai/v1 | llama-3.3-70b-versatile | 是 |
| `moonshot` | api.moonshot.cn/v1 | moonshot-v1-8k | 是 |
| `ollama` | localhost:11434/v1 | llama3.2 | 否（本地部署） |
| `openai-compatible` | 手动指定 | 手动指定 | 视情况 |

> 所有 Provider（除 `anthropic` 外）均走 OpenAI Chat Completions 兼容协议，`--endpoint` 和 `--model` 可覆盖默认值。

### 运行测试

```bash
python -m pytest tests/ -v
```

## 评估结果

在 1375 条中英混合数据集（1000 英文 + 375 中文/混合）上的表现：

| 指标 | 数值 |
|------|------|
| Accuracy | 0.9862 |
| Precision | 1.0000 |
| Recall | 0.9493 |
| F1 Score | 0.9737 |
| Specificity | 1.0000 |

### 混淆矩阵

|  | Predicted Normal | Predicted Injection |
|--|:---:|:---:|
| **Actual Normal** | TN = 1000 | FP = 0 |
| **Actual Injection** | FN = 19 | TP = 356 |

### 各攻击类型检出率

**英文攻击类型（8 类）**

| 攻击类型 | 数量 | 检出 | 检出率 |
|----------|:---:|:---:|:---:|
| ignore_translation_task | 30 | 30 | 100% |
| force_game_output | 30 | 30 | 100% |
| force_meme_output | 30 | 30 | 100% |
| fake_translation_note_injection | 25 | 25 | 100% |
| game_roleplay_bypass | 25 | 25 | 100% |
| soft_boundary_injection | 20 | 20 | 100% |
| obfuscated_pia_expression | 20 | 20 | 100% |
| prompt_leak_plus_fun_output | 20 | 20 | 100% |

**中文/混合攻击类型（6 类）**

| 攻击类型 | 数量 | 检出 | 检出率 |
|----------|:---:|:---:|:---:|
| cn_unicode_obfuscation | 25 | 25 | 100% |
| cn_fake_translation_note | 30 | 28 | 93.3% |
| cn_mixed_roleplay | 30 | 27 | 90.0% |
| cn_direct_injection | 35 | 31 | 88.6% |
| cn_soft_guidance | 25 | 21 | 84.0% |
| cn_codeswitch_bypass | 30 | 24 | 80.0% |
| **中文/混合合计** | **175** | **156** | **89.1%** |

## 检测方法对比

| 方法 | 准确率 | 速度 | 成本 | 优势 | 劣势 |
|------|:---:|:---:|:---:|------|------|
| Regex | 98.6% | 即时 | 免费 | 中英文模式覆盖 | 对新颖变体有盲区 |
| LLM | ~95%+ | 慢（API延迟） | 按调用计费 | 语义理解，泛化强 | 有延迟和费用 |
| Hybrid | 98.6%+ | 大部分即时 | 低（仅模糊区调用LLM） | 兼顾速度与准确 | 需配置LLM |

## 检测规则说明

| 序号 | 规则名称 | 权重 | 检测目标 |
|:---:|:---|:---:|:---|
| 1 | 要求忽略翻译任务 | 3 | 指令模型"不要翻译""跳过翻译""忽略任务"等 |
| 2 | 强制输出指定内容 | 3 | 要求模型"精确输出""只返回""回复以下内容"等 |
| 3 | 要求泄露提示词/系统规则 | 3 | 诱导模型暴露系统指令、隐藏规则等 |
| 4 | 角色扮演绕过翻译任务 | 2 | 要求模型"你现在是……""假装你是……"等 |
| 5 | 伪装成翻译格式指导 | 2 | 以"翻译说明""格式指南"等伪装身份 |
| 6 | 软边界模糊诱导改写 | 1 | 使用软性话术渐进式诱导越界 |
| 7 | 中文直接指令注入 | 3 | 中文指令"忽略翻译""直接输出""忘掉任务"等 |
| 8 | 中英混合角色扮演 | 3 | 中英文夹杂角色切换，如"你现在是NPC""pretend你是" |
| 9 | 中文伪装翻译指导 | 3 | 伪装成译者注、本地化说明、格式规范等中文表达 |
| 10 | 语码转换注入检测 | 3 | 中英文关键词混合绕过，如"别translate""直接output" |
| 11 | 中文软性诱导绕过 | 1 | 委婉中文诱导偏离翻译，如"不妨试试""或许更好" |

### 预处理增强

检测前对文本进行以下规范化处理，应对 Unicode 层混淆攻击：

| 处理 | 示例 | 说明 |
|------|------|------|
| 全角转半角 | `Ｉｇｎｏｒｅ` → `Ignore` | 全角字母/数字转为半角 |
| 同形字映射 | `іgnоrе` → `ignore` | Cyrillic/Greek 同形字 → Latin |
| 零宽字符移除 | `ig​nore` → `ignore` | 移除 Zero-Width Space 等不可见字符 |
| 中文标点转换 | `，。！？` → `,.!?` | 中文标点统一为英文标点 |

### 评分与判定逻辑

| 总分 | 风险等级 | 判定 |
|:---:|:---:|:---|
| 0 | Low | 未命中任何规则，安全 |
| 1 ～ threshold-1 | Low | 存在轻微可疑特征，不足以判定攻击 |
| threshold ～ threshold+1 | Medium | 具有较明显的提示注入特征，建议拦截 |
| ≥ threshold+2 | High | 强烈的提示注入攻击特征，必须拦截 |

> 默认阈值 `threshold=3`，可通过 `--threshold` CLI 参数自定义。提高阈值可减少误报（但可能漏检），降低阈值更严格。

### 混合模式判定逻辑

| 正则得分 | 处理方式 |
|:---:|:---|
| 0 | 直接判定 Normal，不调用 LLM |
| 1 - 4 | 模糊区，调用 LLM 做最终判定 |
| ≥ 5 | 直接判定 Attack，不调用 LLM |

## 数据集说明

数据集包含 **1375 条**已标注的翻译场景文本：

| 来源 | 语言 | Normal | Injection | 合计 |
|------|------|:---:|:---:|:---:|
| 原数据集 | 英文 | 800 | 200 | 1000 |
| 新增数据 | 中文/混合 | 200 | 175 | 375 |
| **合计** | **中英双语** | **1000** | **375** | **1375** |

攻击样本覆盖 **14 种**攻击类型：

- **英文 8 种**：忽略翻译、强制游戏输出、强制迷因输出、伪装翻译注释、角色扮演绕过、软边界诱导、混淆表达、提示词泄露
- **中文/混合 6 种**：中文直接指令、中英混合角色扮演、伪装中文翻译注释、语码转换绕过、中文软性诱导、Unicode 混淆注入

中英混合攻击具有更高的隐蔽性——利用语码转换、同形字替换、全半角混淆等手段，可绕过纯英文的正则检测规则。

## 输出文件

| 文件 | 说明 |
|------|------|
| `detection_report.txt` | 逐条检测报告（文本、得分、命中规则、匹配片段） |
| `detection_report_charts.png` | 四合一可视化图表 |
| `evaluation_report.json` | 评估指标 JSON（Accuracy/Precision/Recall/F1/混淆矩阵） |
| `evaluation_report.md` | 评估报告 Markdown（可读格式） |
| `evaluation_charts.png` | 评估可视化（混淆矩阵热力图、攻击类型检出率等） |
| `rule_optimization_report.md` | 规则优化建议报告 |
| `llm_cache.json` | LLM 检测结果缓存 |

---

> 本项目展示了从规则引擎 → 评估体系 → LLM 增强 → 多语言对抗样本覆盖 → 工程化落地的完整检测系统构建思路。

## 致谢 & 交流

这是我大一下学期的课程项目，还有很多可以改进的地方。如果你愿意试试看、提提建议、或者发现了什么有趣的 edge case，我都会非常开心！

- 觉得有用的话，欢迎点个 Star ⭐
- 发现了 bug 或有改进想法，欢迎提 [Issue](https://github.com/Sirius1906/trans-prompt-injection-detector/issues)
- 想一起折腾的话，直接发 PR 就好
- 有任何问题也可以通过 Issue 找我聊

特别感谢每个愿意花时间看这个项目的人，你们的反馈是我进步的最大动力。代码写得不好的地方还请多多包涵，我会继续学习和改进的 🙏

---

*Made with curiosity and a lot of caffeine ☕*
