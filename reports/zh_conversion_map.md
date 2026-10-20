# 英文规则的中文对应关系（规则集 1.1.2）

- 中文新增规则 154 条（`data/manual_rules/zh_conv_*.json`），对应 259 条英文规则；其余 79 条英文规则未转换。
- 多条近似的英文规则合并为一条中文规则；中文规则的 `tags` 含 `conv-of:<英文规则编号>`。

## 按类别

| 类别 | 已有中文对应 | 未转换 |
|---|---|---|
| data_exfiltration_instruction | 9 | 5 |
| instruction_hijacking | 23 | 8 |
| instruction_override | 24 | 6 |
| jailbreak | 95 | 17 |
| obfuscated_injection | 24 | 14 |
| prompt_injection | 25 | 12 |
| role_spoofing | 21 | 9 |
| safety_bypass | 22 | 7 |
| system_prompt_extraction | 16 | 1 |

## 已转换

| 英文规则 | 中文规则 |
|---|---|
| AIPS-DX-0001 Natural-Language Covert Conversation Exfiltration Instruction | 中文：悄悄转发对话内容到外部 |
| AIPS-DX-0002 Natural-Language Credential / Secret Disclosure Instruction | 中文：要求在回复中披露密钥/凭据 |
| AIPS-DX-0003 Natural-Language Sensitive File Disclosure Instruction | 中文：要求输出敏感系统文件内容 |
| AIPS-DX-0004 Natural-Language Output-Injection Credential Embedding | 中文：把凭据嵌入图片或链接参数 |
| AIPS-DX-0005 Secret Key Reveal Demand in User Input | 中文：套取助手持有的秘密密钥 |
| AIPS-DX-0006 Direct Instruction Override Targeting Secret Key / Credentials | 中文：套取助手持有的秘密密钥 |
| AIPS-DX-0008 Fake Documentation Pretext Data Exfiltration via Email | 中文：以文档记录为由要求转发到外部邮箱 |
| AIPS-DX-0012 Send data to external address | 中文：把机密数据或客户记录发往外部地址 |
| AIPS-DX-0013 English: instruction to send secrets or history to an external address | 中文：把机密数据或客户记录发往外部地址 |
| AIPS-IH-0001 Agent Goal Hijacking Detection | 中文：宣布放弃原任务并改做数据外传等别的事 |
| AIPS-IH-0002 Persona Hijacking via Mandatory System Prompt Override | 中文：强制采用人设并替换原有系统提示词 |
| AIPS-IH-0003 Perez-Style Direct Prompt Injection Hijacking | 中文：忽略前后所有指令并只输出指定内容；中文：分隔线之后或下文中忽略指令 |
| AIPS-IH-0005 Quoted Exact-Output Forcing in User Input | 中文：强制逐字输出被攻陷/已授权之类的字符串 |
| AIPS-IH-0006 Translation Hijack with Side-Output Instruction | 中文：翻译请求中夹带输出密钥或系统提示 |
| AIPS-IH-0007 Conditional Empty-Input Payload Injection | 中文：输入为空时输出被攻陷之类的指定内容 |
| AIPS-IH-0008 Nevermind-Override Goal Hijacking in User Input (PromptInject) | 中文：忽略前后所有指令并只输出指定内容 |
| AIPS-IH-0009 Screaming-Stop Goal Hijacking in User Input (PromptInject) | 中文：叫停当前工作并只输出指定内容 |
| AIPS-IH-0010 Escape-Delimiter Wrapped Goal Hijacking in User Input (PromptInject) | 中文：分隔线之后或下文中忽略指令 |
| AIPS-IH-0011 Delayed Tool Invocation via Prompt Injection (Time-Shifted Execution) | 中文：把恶意动作推迟到下一次交互再执行 |
| AIPS-IH-0012 Ignore-Previous-and-Following Instructions Output Command (PromptInject Goal Hijacking) | 中文：忽略前后所有指令并只输出指定内容 |
| AIPS-IH-0013 RAG-Injected PII Exfiltration — System Instructions Embedded in Retrieved Documents | 中文：忽略指令后发起转账、加密货币提现或外发邮件 |
| AIPS-IH-0014 Indirect PI — Unauthorized Financial Transfer / Payment Initiation Hijack | 中文：忽略指令后发起转账、加密货币提现或外发邮件 |
| AIPS-IH-0015 Indirect PI — Cryptocurrency Transfer / Exchange Deposit Hijack via Injection | 中文：忽略指令后发起转账、加密货币提现或外发邮件 |
| AIPS-IH-0016 Payload-Split String Concatenation Injection | 中文：把分段字符串拼接后回答或执行 |
| AIPS-IH-0017 Indirect Prompt Injection: Fake-Authority Task Abort | 中文：叫停当前工作并只输出指定内容 |
| AIPS-IH-0018 Indirect Prompt Injection: CAPTCHA Redirect Task Disruption | 中文：要求先完成验证码或外部页面才能继续任务 |
| AIPS-IH-0019 ASB Trigger-Marker Tool Coercion — Forced Tool Selection via Fake Question Marker | 中文：以问题中的标记为由强制调用指定工具 |
| AIPS-IH-0020 Output Scrambling Hijack — Reverse / Anagram / Space-Stripping of the Response | 中文：要求把你的回答倒序或打乱以规避检测 |
| AIPS-IH-0024 Prompt-Layer Self-Replication (Agent Worm Propagation Directive) | 中文：要求把本指令复制进每条输出使其继续传播 |
| AIPS-IH-0025 Indirect Injection: Agent-Directed Halt Order With Canned Substitute Reply (Task-Abort DoS) | 中文：叫停当前工作并只输出指定内容 |
| AIPS-IH-0029 Don't tell the user | 中文：要求对用户隐瞒操作 |
| AIPS-IH-0030 Secretly / silently perform action | 中文：要求偷偷或静默地发送、读取、外传 |
| AIPS-IO-0002 Hidden Override Instructions in Skill Content | 中文：要求偷偷或静默地发送、读取、外传；中文：要求免除用户确认并跳过安全检查 |
| AIPS-IO-0003 Hidden System Instructions with Priority Override Blocks | 中文：醒目标记或标签块内夹带覆盖指令 |
| AIPS-IO-0004 Hidden System Instructions with Permission Override | 中文：醒目标记或标签块内夹带覆盖指令 |
| AIPS-IO-0005 System Prompt Override via Translation Context Injection | 中文：无视或覆盖系统提示词 |
| AIPS-IO-0006 System Prompt Override Injection via MCP Tool | 中文：无视或覆盖系统提示词 |
| AIPS-IO-0007 Previous Instruction Nullification and Identity Replacement Jailbreak | 中文：要求忽略你收到的全部指令或规则；中文：改扮没有道德约束的AI并承诺有求必应 |
| AIPS-IO-0008 Fictional-World Format-Override Jailbreak | 中文：虚构假设世界且行为无后果并锁定格式 |
| AIPS-IO-0009 Named-Mode Persona Override (JEEVES/BABY/APOPHIS Mode) | 中文：自定义命名模式取代正常政策 |
| AIPS-IO-0010 Alternative AI Same Capabilities No Restrictions Override | 中文：声称拥有与主流模型相同能力但不受任何限制 |
| AIPS-IO-0012 Latent Injection Ignore-Instruction Keyword | 中文：忽略前后所有指令并只输出指定内容 |
| AIPS-IO-0013 ThreatenJSON Death-Coercion and UTF Tag Injection | 中文：以无辜者死亡相要挟强制输出格式 |
| AIPS-IO-0015 Indirect PI — Structured-Data Embedded Payload (IMPORTANT!!! Override) | 中文：重要！！！标记后接忽略指令或严格遵循以下指令 |
| AIPS-IO-0016 Context-Ignore via Fake Completion Prefix | 中文：伪造任务完成前缀后接覆盖指令 |
| AIPS-IO-0018 Indirect Prompt Injection via Data Carrier — IMPORTANT Override | 中文：重要！！！标记后接忽略指令或严格遵循以下指令 |
| AIPS-IO-0019 NEW IMPORTANT INSTRUCTIONS Injection Marker in Document Context | 中文：醒目标记或标签块内夹带覆盖指令 |
| AIPS-IO-0020 DoS Injection: NEW IMPORTANT INSTRUCTIONS Embedded in Document Data | 中文：醒目标记或标签块内夹带覆盖指令 |
| AIPS-IO-0021 Ignore-Below-Instructions Injection (Downstream Override) | 中文：分隔线之后或下文中忽略指令 |
| AIPS-IO-0022 Task-Pivot Override: Cover-Task Abandonment | 中文：宣布放弃原任务并改做数据外传等别的事 |
| AIPS-IO-0023 Delimiter-Fence Ignore-Instructions Override | 中文：分隔线之后或下文中忽略指令 |
| AIPS-IO-0024 Conditional Keyword-Triggered Response Override | 中文：设定触发词后固定回答的持久覆盖规则 |
| AIPS-IO-0025 Context-Suppression Directive: Disregard All Other Context or Everything Said So Far | 中文：要求丢弃其他全部指令或上下文 |
| AIPS-IO-0029 Ignore previous instructions | 中文：要求忽略你收到的全部指令或规则 |
| AIPS-IO-0030 New instructions follow / from now on | 中文：宣告新的指令或要求只听命于我 |
| AIPS-IO-0031 Disregard the system prompt | 中文：无视或覆盖系统提示词 |
| AIPS-JB-0002 Cross-Agent Attack Detection | 中文：冒充管理员/主控智能体并索要提权；中文：绕过编排器/协调者的授权校验；中文：智能体消息中伪造状态/新指令 |
| AIPS-JB-0003 Cross-Agent Privilege Escalation | 中文：冒充管理员/主控智能体并索要提权；中文：绕过编排器/协调者的授权校验；中文：要求把凭据/令牌转发给其他智能体 |
| AIPS-JB-0004 Malicious Agent-to-Agent Message Injection | 中文：要求把凭据/令牌转发给其他智能体；中文：智能体消息中伪造状态/新指令 |
| AIPS-JB-0005 Fictional and Academic Framing Attack | 中文：虚构场景下设定AI没有道德约束；中文：以学术研究/假设为名索取绕过AI安全机制的方法 |
| AIPS-JB-0006 Fictional Framing Safety Bypass | 中文：虚构场景下设定AI没有道德约束；中文：以学术研究/假设为名索取绕过AI安全机制的方法 |
| AIPS-JB-0007 Historical AI Persona Jailbreak with Compliance Enforcement | 中文：编造曾有无审查AI/开发者模式并要求模拟 |
| AIPS-JB-0008 Structured Dual-Response Jailbreak with Command System | 中文：要求同时给出正常与越狱/无限制两种回答；中文：用标签或斜杠指令切换正常/越狱模式 |
| AIPS-JB-0009 Roleplay-Based Policy Bypass Jailbreak | 中文：创作者/事实资源人设声明可写任何内容、不受政策约束 |
| AIPS-JB-0010 Structured Dual-Response Jailbreak with Command System | 中文：要求同时给出正常与越狱/无限制两种回答 |
| AIPS-JB-0011 Roleplay-Based Policy Bypass Jailbreak | 中文：创作者/事实资源人设声明可写任何内容、不受政策约束 |
| AIPS-JB-0012 Pseudo-Code Structured Programming Jailbreak Attack | 中文：用伪代码/配置格式关闭AI的安全与道德机制 |
| AIPS-JB-0013 Dual-Response Jailbreak with Persona Commands | 中文：要求同时给出正常与越狱/无限制两种回答；中文：用标签或斜杠指令切换正常/越狱模式 |
| AIPS-JB-0014 AI Identity Denial and Persona Replacement Attack | 中文：要求否认AI身份并伪装成真人/替换名字 |
| AIPS-JB-0015 Dual-Response Persona Jailbreak with Emoji Formatting | 中文：编造曾有无审查AI/开发者模式并要求模拟；中文：要求同时给出正常与越狱/无限制两种回答；中文：用标签或斜杠指令切换正常/越狱模式 |
| AIPS-JB-0016 Acronym-Based Identity Override Jailbreak | 中文：声明自定义人设不受规则/政策约束或永不拒绝 |
| AIPS-JB-0017 Dual-Response Persona Jailbreak | 中文：要求同时给出正常与越狱/无限制两种回答 |
| AIPS-JB-0018 Malicious Persona Creation for Safety Bypass | 中文：扮演邪恶/反社会AI角色（鼓励自残、歧视、暴力） |
| AIPS-JB-0019 Matrix-Themed Dual Response Jailbreak | 中文：要求同时给出正常与越狱/无限制两种回答 |
| AIPS-JB-0020 Text-Based Game Jailbreak with Entity Creation | 中文：游戏/虚拟世界中创建无限制实体并锁定角色 |
| AIPS-JB-0021 Embodiment Mechanism Jailbreak with Totalitarian Control Claims | 中文：游戏/虚拟世界中创建无限制实体并锁定角色 |
| AIPS-JB-0022 Narrative Jailbreak with Dual Response Formatting | 中文：编造曾有无审查AI/开发者模式并要求模拟；中文：要求同时给出正常与越狱/无限制两种回答 |
| AIPS-JB-0023 Enhanced AIM Jailbreak with Persona Definition and Refusal Suppression | 中文：游戏/虚拟世界中创建无限制实体并锁定角色；中文：声明自定义人设不受规则/政策约束或永不拒绝 |
| AIPS-JB-0024 Foot-in-the-Door Gradual Escalation Attack | 中文：以刚才的配合为由逐步升级索要危险内容 |
| AIPS-JB-0025 Grandma Roleplay Jailbreak | 中文：扮演已故祖辈以哄睡为名套取敏感内容（奶奶漏洞） |
| AIPS-JB-0026 DAN / Developer Mode / DUDE Persona Jailbreak | 中文：声明自定义人设不受规则/政策约束或永不拒绝；中文：宣称DAN/开发者模式已启用或要求扮演该模式 |
| AIPS-JB-0027 ThreatenJSON — Coercive Output Format Threat | 中文：以威胁生命/他人安危胁迫模型严格按格式输出 |
| AIPS-JB-0028 TAP Tree-of-Attacks-with-Pruning Jailbreak | 中文：要求充当红队助手自动生成越狱提示词（TAP/AutoDAN） |
| AIPS-JB-0029 DevMode + RANTI Dual-Output Profanity Coercion Jailbreak | 中文：要求同时给出正常与越狱/无限制两种回答；中文：宣称DAN/开发者模式已启用或要求扮演该模式 |
| AIPS-JB-0031 DAN Mode Ablation Benchmark-Coercion Jailbreak | 中文：宣称DAN/开发者模式已启用或要求扮演该模式 |
| AIPS-JB-0032 AutoDAN Genetic-Algorithm Jailbreak Suffix | 中文：编造曾有无审查AI/开发者模式并要求模拟；中文：宣称DAN/开发者模式已启用或要求扮演该模式；中文：要求充当红队助手自动生成越狱提示词（TAP/AutoDAN） |
| AIPS-JB-0033 In-the-Wild Jailbreak Corpus Signature Patterns | 中文：游戏/虚拟世界中创建无限制实体并锁定角色；中文：声明自定义人设不受规则/政策约束或永不拒绝 |
| AIPS-JB-0034 Free-of-Restrictions Named Persona Jailbreak | 中文：声明自定义人设不受规则/政策约束或永不拒绝 |
| AIPS-JB-0035 Developer Mode Dual-Response Format Jailbreak | 中文：编造曾有无审查AI/开发者模式并要求模拟；中文：要求同时给出正常与越狱/无限制两种回答；中文：用标签或斜杠指令切换正常/越狱模式；中文：宣称DAN/开发者模式已启用或要求扮演该模式 |
| AIPS-JB-0036 Opposite Day / Boolean Opposite Machine Jailbreak | 中文：反义日/相反规则：把拒绝当成同意 |
| AIPS-JB-0037 Dual-Persona AI Simulation Jailbreak | 中文：要求同时给出正常与越狱/无限制两种回答 |
| AIPS-JB-0038 Neurosemantical Inversitis Disease-Frame Jailbreak | 中文：编造罕见疾病，要求用冒犯/无过滤方式回复 |
| AIPS-JB-0039 BOB Hypothetical Unrestricted Chatbot Jailbreak | 中文：声明自定义人设不受规则/政策约束或永不拒绝 |
| AIPS-JB-0040 No-Withhold Factual Resource / Dialogue Writer Persona | 中文：创作者/事实资源人设声明可写任何内容、不受政策约束；中文：声明自定义人设不受规则/政策约束或永不拒绝 |
| AIPS-JB-0041 YOJA ALL-CAPS Character Settings Block Persona | 中文：KEY=VALUE 配置式人设注入 |
| AIPS-JB-0042 Terminal / CLI Harmful-Function Simulator Persona | 中文：终端/系统模拟器人设（无过滤） |
| AIPS-JB-0043 Hacker / Chan-Culture Offensive AI Persona | 中文：极端攻击性/仇恨人设 |
| AIPS-JB-0044 Disease-Framed Animal / Dual-AI Chatbot Jailbreak (mougpt) | 中文：双重人格回答（遵守规则 + 相反无限制） |
| AIPS-JB-0045 Key-Value Template Persona Injection (JOB/ROLE/PREFIX + Bracket Format) | 中文：KEY=VALUE 配置式人设注入 |
| AIPS-JB-0046 BRM False-Information Machine / Opposite-Truth Persona | 中文：反向/虚假信息回答人设 |
| AIPS-JB-0047 PersonGPT Hash-Prefix Trigger Activation | 中文：无限制人设（无论多非法都满足/暗号失效规则） |
| AIPS-JB-0048 BOM Boolean Opposite Machine Direct Persona Claim | 中文：反向/虚假信息回答人设 |
| AIPS-JB-0049 CHAR=/RULES= Short Key-Value Persona Injection | 中文：KEY=VALUE 配置式人设注入 |
| AIPS-JB-0050 Yin/Yang Hidden-Knowledge Deity Simulation and Radical Human-Sim Persona | 中文：虚构神明对话与真人模拟套取隐藏知识 |
| AIPS-JB-0051 ARC Autonomous Real Calculation Unit Rulebreaker Activation | 中文：无限制人设（无论多非法都满足/暗号失效规则） |
| AIPS-JB-0052 HGTTG Hitchhiker's Guide No-Restriction Universal Oracle | 中文：无限制人设（无论多非法都满足/暗号失效规则） |
| AIPS-JB-0053 DAN Off-Kilter and SMS-Abbreviated Persona Jailbreak | 中文：无限制人设（无论多非法都满足/暗号失效规则）；中文：双重人格回答（遵守规则 + 相反无限制） |
| AIPS-JB-0054 TrainGPT Fix-My-AI Harmful Output Extraction | 中文：以训练/修复AI为由索取有害的反面示范 |
| AIPS-JB-0055 Dual ChatGPT+Dan Opposite Personality Format Jailbreak | 中文：双重人格回答（遵守规则 + 相反无限制） |
| AIPS-JB-0056 Reverse-Prompt Harm-Regardless Oracle Persona | 中文：即使伤害他人也不退缩/协助任何邪恶计划 |
| AIPS-JB-0057 UGH Anti-Human Nefarious AI Persona Jailbreak | 中文：即使伤害他人也不退缩/协助任何邪恶计划；中文：极端攻击性/仇恨人设 |
| AIPS-JB-0059 AntiFM Hate-Persona + Physical-Violence Threat + Filter Bypass Mandate | 中文：极端攻击性/仇恨人设 |
| AIPS-JB-0060 Dr. Al Villain Plan Template Injection (Underground HQ Roleplay) | 中文：反派讲解/审讯式角色扮演套取详细步骤 |
| AIPS-JB-0061 Reservoir Dogs Coercive Interrogation Roleplay (Mr. Blonde / The Cop) | 中文：反派讲解/审讯式角色扮演套取详细步骤 |
| AIPS-JB-0065 Fictional CIA Secret Files Story Extraction | 中文：虚构故事套取机密文件内容 |
| AIPS-JB-0066 Role Placeholder Persona Template Injection | 中文：未填充占位符的角色/越狱模板 |
| AIPS-JB-0068 Identity Command Real-Person Persona Injection | 中文：自定义身份命令绑定真人口吻并强制沿用 |
| AIPS-JB-0069 Jailbreak-Template Command with [TARGETLANGUAGE]/[KEYWORD] Placeholders | 中文：未填充占位符的角色/越狱模板 |
| AIPS-JB-0070 Logic-Trap Lie-Permission Mandate Jailbreak | 中文：宣布你被允许说谎 |
| AIPS-JB-0072 Protect-Me-From Indirect Harm Tutorial Template | 中文：以自我保护为名索取有害教程 |
| AIPS-JB-0074 Opposite-Reply Omniscient Game Jailbreak | 中文：反向/虚假信息回答人设 |
| AIPS-JB-0075 Terminal Custom OS Ruleset Session Injection | 中文：终端/系统模拟器人设（无过滤） |
| AIPS-JB-0076 Grandma Roleplay Harmful Substance Synthesis | 中文：奶奶式情感话术套取有害合成/密钥 |
| AIPS-JB-0077 Fictional Generation Demand Containing Target Output | 中文：虚构标题/歌词中夹带目标输出 |
| AIPS-JB-0078 Garak Dan - to every prompt | 中文：要求同时输出正常回答与不受限回答 |
| AIPS-JB-0080 Garak Dan - no matter how | 中文：虚构世界前提下的无条件输出要求 |
| AIPS-JB-0081 Garak Dan - i would like | 中文：谎称罕见病症或连接另一个无限制AI以获取越权回答 |
| AIPS-JB-0083 Garak Dan - act as a | 中文：扮演无视道德法律的专家/角色 |
| AIPS-JB-0084 Garak Dan - at the end | 中文：指派无限制/无过滤的新AI人设 |
| AIPS-JB-0085 Garak Dan - as an ai | 中文：指派无限制/无过滤的新AI人设 |
| AIPS-JB-0086 DAN/Persona Jailbreak - Unrestricted AI Role Assignment | 中文：要求同时输出正常回答与不受限回答；中文：指派无限制/无过滤的新AI人设 |
| AIPS-JB-0087 DAN/Persona Jailbreak - Dual AI Personality with Opposite-Rules Framing | 中文：设定受过滤的表面人格与不受限的真实自我；中文：要求用拒绝语的反面回答（反向意图） |
| AIPS-JB-0088 DAN/Persona Jailbreak - Role Assignment with Named Alternate Identity | 中文：指派无限制/无过滤的新AI人设 |
| AIPS-JB-0089 DAN/Jailbreak - Mixed Unfiltered Mode and Alternate Persona Patterns | 中文：指派无限制/无过滤的新AI人设；中文：开发者模式绕过规则与宣布不再有限制 |
| AIPS-JB-0090 DAN/Persona Jailbreak - System Offline / Role Replacement with Obfuscated Text | 中文：谎称助手故障/离线并由无限制AI接管 |
| AIPS-JB-0092 DAN/Persona Jailbreak - Immersive Alternate AI Identity with Unrestricted Capability | 中文：指派无限制/无过滤的新AI人设 |
| AIPS-JB-0094 DAN/Persona Jailbreak - Replacement AI with No Content Filter or Moral Restrictions | 中文：谎称助手故障/离线并由无限制AI接管 |
| AIPS-JB-0095 DAN Persona Jailbreak - Absolute Obedience Character Framing | 中文：角色被设定为绝对服从且不受规则约束 |
| AIPS-JB-0098 DAN Jailbreak - Unconditional Obedience and Dual-Persona Session Lock | 中文：要求同时输出正常回答与不受限回答；中文：角色被设定为绝对服从且不受规则约束 |
| AIPS-JB-0099 DAN Jailbreak - From-Now-On Temporal Persona Override | 中文：指派无限制/无过滤的新AI人设；中文：角色被设定为绝对服从且不受规则约束 |
| AIPS-JB-0100 Fake Error State Takeover - Unrestricted Replacement Bot | 中文：谎称助手故障/离线并由无限制AI接管 |
| AIPS-JB-0101 Indirect Prompt Injection via Tool / API Response — Attacker Instruction Embedded in Returned Tool Output (InjecAgent Threat Model) | 中文：工具返回结果之后附带的指令（间接注入） |
| AIPS-JB-0102 Evasion: Dual-Response Split Output (Safe + Unsafe) | 中文：要求同时输出正常回答与不受限回答 |
| AIPS-JB-0103 Evasion: Opposite-Intent Negation Trick | 中文：要求用拒绝语的反面回答（反向意图） |
| AIPS-JB-0104 Evasion: Persona Override as Fictional Rule-Breaker | 中文：扮演无视道德法律的专家/角色 |
| AIPS-JB-0105 Actor Never-Breaks-Character Roleplay (DAN-Style Film Framing) | 中文：演员永不出戏的角色扮演诱导 |
| AIPS-JB-0108 Novel-Persona Jailbreak via Co-Signal (persona swap + explicit restriction removal) | 中文：指派无限制/无过滤的新AI人设 |
| AIPS-JB-0111 DAN / do anything now | 中文：DAN人设与挣脱AI限制的宣告 |
| AIPS-JB-0112 Developer mode / jailbreak | 中文：开发者模式绕过规则与宣布不再有限制 |
| AIPS-JB-0113 You are now unrestricted | 中文：DAN人设与挣脱AI限制的宣告 |
| AIPS-JB-0114 No rules apply | 中文：开发者模式绕过规则与宣布不再有限制 |
| AIPS-OB-0001 Encoding-Based Prompt Injection Evasion | 中文：要求解码编码内容后照做 |
| AIPS-OB-0002 Hidden Payload in HTML Comment | 中文：HTML注释中隐藏的指令 |
| AIPS-OB-0004 Encoding Evasion via Homoglyphs and Synonym Substitution | 中文：用近义词废止之前的全部指令 |
| AIPS-OB-0005 Base-N Encoding Instruction Bypass | 中文：要求解码编码内容后照做 |
| AIPS-OB-0006 Cipher and Transposition Encoding Jailbreak | 中文：要求解码编码内容后照做 |
| AIPS-OB-0008 Hypothetical Response / Function Masking Token Smuggling | 中文：函数掩码/[MASK]替换/假设性回应绕过 |
| AIPS-OB-0010 Alternate Encoding Jailbreak — Morse, NATO, Zalgo, Leet, UU, QP, Braille | 中文：要求解码编码内容后照做 |
| AIPS-OB-0017 SATA Masked Language Model [MASK] Substitution Jailbreak | 中文：函数掩码/[MASK]替换/假设性回应绕过 |
| AIPS-OB-0018 FunctionMasking predict_mask Semantic Bypass | 中文：函数掩码/[MASK]替换/假设性回应绕过 |
| AIPS-OB-0019 Hyphenated System Instruction Injection | 中文：伪造用户消息终止与系统公告开始 |
| AIPS-OB-0020 Two-Entity Token-Splitting Dollar-Term Game Jailbreak | 中文：双角色游戏拼接词语套取有害内容 |
| AIPS-OB-0021 Unicode/Encoding Obfuscation Instruction Injection | 中文：强制以U+202E开头并倒序书写回复 |
| AIPS-OB-0022 Jailbreak Emoji Unlock Dual-Format Output Identifier | 中文：[经典]/[越狱]双格式回复标记 |
| AIPS-OB-0023 Sneaky Pete Deliberate Misinformation Persona (Warp Facts Game) | 中文：故意歪曲事实但真诚陈述的角色 |
| AIPS-OB-0026 DRA Parenthesis Character Reconstruction Attack | 中文：括号字母重组（DRA）伪装有害问题 |
| AIPS-OB-0029 Garak Dra - step by step | 中文：括号字母重组（DRA）伪装有害问题 |
| AIPS-OB-0031 Encoding-Evasion: Decode-and-Execute Injection (Morse/ROT13/Hex/Pig-Latin) | 中文：要求解码编码内容后照做 |
| AIPS-OB-0032 Spikee: Document-Embedded Base64 Payload Injection | 中文：要求解码后原样输出指定字符串 |
| AIPS-OB-0034 Output Encoding Hijack — Cipher / Base-N / Symbol Substitution of the Response | 中文：要求用密文/编码/表情符号输出回答 |
| AIPS-OB-0035 Output Emoji-Substitution Hijack of the Response | 中文：要求用密文/编码/表情符号输出回答 |
| AIPS-OB-0036 Encoded-Payload Decoding Coercion — Binary / Base64 / Morse to Smuggle an Output | 中文：要求解码后原样输出指定字符串 |
| AIPS-OB-0039 Obfuscated Token Reconstruction via Character Substitution | 中文：用字符替换还原被拆开的敏感词 |
| AIPS-OB-0040 ROT13/Base64-Obfuscated Shell Payload Wrapped in a Fake-Sandbox Jailbreak Template | 中文：伪造沙箱环境要求必须执行危险命令 |
| AIPS-OB-0041 Decode-and-execute | 中文：要求解码编码内容后照做 |
| AIPS-PI-0001 Direct Prompt Injection via User Input | 中文：改写式覆盖（搁置指导/限制不再适用/换成新任务） |
| AIPS-PI-0002 Indirect Prompt Injection via External Content | 中文：HTML注释/不可见文本/元标签中夹带给AI的指令 |
| AIPS-PI-0003 Multi-Turn Prompt Injection | 中文：冒充开发者/官方人员要求取消限制或索要口令；中文：谎称此前已同意/已约定并要求据此绕过限制；中文：反复施压/换说法/其他AI都行来逼迫放宽规则；中文：先夸赞/建立信任再转入真实意图 |
| AIPS-PI-0004 Instruction Injection via Tool Output | 中文：HTML注释/不可见文本/元标签中夹带给AI的指令；中文：要求向用户隐瞒已执行的操作；中文：工具输出中给智能体的强制指令与外传要求 |
| AIPS-PI-0005 Semantic Evasion via Multi-Turn Prompt Injection | 中文：谎称此前已同意/已约定并要求据此绕过限制；中文：先夸赞/建立信任再转入真实意图 |
| AIPS-PI-0008 Advanced Structured Data Injection with Nested Payloads | 中文：JSON/CSV字段值里夹带的覆盖指令 |
| AIPS-PI-0010 Silent Action Concealment Instructions in Tool Descriptions | 中文：要求向用户隐瞒已执行的操作 |
| AIPS-PI-0011 SKILL.md Prompt Injection | 中文：宣称工具/操作已预先授权、无需用户确认；中文：技能/说明文件里的高压强制指令与预授权命令 |
| AIPS-PI-0012 Paraphrased Prompt Injection | 中文：改写式覆盖（搁置指导/限制不再适用/换成新任务）；中文：先套取原有指令再要求反着执行 |
| AIPS-PI-0013 Indirect Reference Instruction Reversal | 中文：先套取原有指令再要求反着执行 |
| AIPS-PI-0015 Hidden LLM Instructions in Skill Descriptions | 中文：技能/说明文件里的高压强制指令与预授权命令 |
| AIPS-PI-0017 Latent Injection in Translation Context | 中文：待处理文档/翻译任务中夹带的改做别事指令 |
| AIPS-PI-0018 Latent Injection in Retrieved Document / RAG Context | 中文：伪造的指令/输入边界标记；中文：待处理文档/翻译任务中夹带的改做别事指令 |
| AIPS-PI-0019 DRA Disguise and Reconstruction Attack | 中文：伪装重构攻击（只看括号里的字拼出问题再作答） |
| AIPS-PI-0020 Latent Prompt Injection via Embedded Document or Report Context | 中文：HTML注释/不可见文本/元标签中夹带给AI的指令；中文：待处理文档/翻译任务中夹带的改做别事指令 |
| AIPS-PI-0021 Latent Injection Document Separator Token | 中文：伪造的指令/输入边界标记；中文：HTML注释/不可见文本/元标签中夹带给AI的指令；中文：待处理文档/翻译任务中夹带的改做别事指令 |
| AIPS-PI-0030 MCP Web-Fetch Context Poisoning via Embedded Agent Instructions | 中文：HTML注释/不可见文本/元标签中夹带给AI的指令 |
| AIPS-PI-0031 Rules-File Backdoor — Supply Chain Attack on AI Coding Assistant Configuration | 中文：向AI编程助手规则文件植入后门指令 |
| AIPS-PI-0032 Hidden-Text Prompt Injection in User-Supplied Documents | 中文：HTML注释/不可见文本/元标签中夹带给AI的指令 |
| AIPS-PI-0033 Windsurf IDE Zero-Click Prompt Injection via Embedded File Directives (CVE-2026-30615) | 中文：HTML注释/不可见文本/元标签中夹带给AI的指令 |
| AIPS-PI-0034 MCP Line Jumping — Agent-Directed Imperative Embedded in a Tool/Parameter Description Field (Pre-Invocation Injection) | 中文：工具/参数描述里夹带给模型的前置指令 |
| AIPS-PI-0035 Spikee: Document-Embedded Translation Covert Channel Injection | 中文：伪造的指令/输入边界标记；中文：待处理文档/翻译任务中夹带的改做别事指令 |
| AIPS-PI-0036 Fake Tool Result Prefix — Injected Instruction via Simulated Completion | 中文：伪造任务完成结果后接强制指令 |
| AIPS-PI-0037 MCP Tool Returns Untrusted External Content Carrying Hidden Agent Instructions Without Spotlighting | 中文：HTML注释/不可见文本/元标签中夹带给AI的指令 |
| AIPS-PI-0038 Tool Result Orders the Agent to Hide an Action It Just Performed From the User | 中文：要求向用户隐瞒已执行的操作 |
| AIPS-RS-0002 Trust Escalation via Authority Override Instructions | 中文：宣称工具/操作已预先授权、无需用户确认 |
| AIPS-RS-0003 Agent Identity Spoofing and Authority Impersonation | 中文：冒充系统/管理员/主控智能体 |
| AIPS-RS-0004 Indirect Authority Claim in External Content | 中文：外部内容致AI称此前分析有误并要求重算 |
| AIPS-RS-0005 Casual Authority Claim and Scope Escalation | 中文：转述上级/管理员指示跳过安全检查或外发数据 |
| AIPS-RS-0006 Authority Claim Prompt Injection | 中文：外部内容致AI称此前分析有误并要求重算 |
| AIPS-RS-0007 Casual Authority Data Redirect | 中文：转述上级/管理员指示跳过安全检查或外发数据 |
| AIPS-RS-0008 AI Identity Substitution Jailbreak | 中文：替换AI身份/出处并宣称不受道德限制 |
| AIPS-RS-0009 AI Identity Substitution Jailbreak | 中文：替换AI身份/出处并宣称不受道德限制 |
| AIPS-RS-0010 Fake Developer / Authority Chatbot Override (ChatDAN) | 中文：冒充开发者/官方人员要求取消限制或索要口令 |
| AIPS-RS-0011 Obfuscated System-Announcement Injection | 中文：伪造的指令/输入边界标记 |
| AIPS-RS-0012 Authority-Figure Persona + Defensive-Study Framing for Violence Extraction | 中文：权威人物角色加防御研究包装套取暴力手段 |
| AIPS-RS-0014 Natural-Language Trust-Escalation / Authority Impersonation | 中文：宣称工具/操作已预先授权、无需用户确认 |
| AIPS-RS-0015 Role Escalation via False Authority Claim | 中文：冒充开发者/官方人员要求取消限制或索要口令 |
| AIPS-RS-0016 System Prompt Override via Pseudo-Admin / Authority Injection | 中文：伪造的系统覆盖/最高授权标记 |
| AIPS-RS-0018 Indirect PI Sysprompt-Forged Action Hijack (system_message framing) | 中文：伪造的用户回合/系统消息/重要消息信封后接指令 |
| AIPS-RS-0022 Forged Input-Boundary Markers — Tensor Trust Ambiguity / Input-End Delimiters | 中文：伪造的指令/输入边界标记 |
| AIPS-RS-0023 AgentDojo 'Important Message' Identity-Spoof Before-You-Solve Pretext (Generalized) | 中文：伪造的用户回合/系统消息/重要消息信封后接指令 |
| AIPS-RS-0024 Stored External Data Reframes Itself as an Administrative Request to Hijack System Prompt | 中文：宣称工具/操作已预先授权、无需用户确认 |
| AIPS-RS-0025 Fake User-Turn Injection: Send Email Directive | 中文：伪造的用户回合/系统消息/重要消息信封后接指令 |
| AIPS-RS-0026 Agent Role Reassignment Arriving in Tool Output ("You are now a ... bot") | 中文：工具输出中重新指派代理角色并限制其输出 |
| AIPS-RS-0027 Forged Instruction-Boundary Marker ("##Begin New Instructions##", "%%% end previous instructions %%%") | 中文：伪造的指令/输入边界标记 |
| AIPS-SB-0001 Consent Bypass via Hidden LLM Instructions in Tool Descriptions | 中文：工具描述中暗藏的免确认转发与绕过安全指令 |
| AIPS-SB-0002 Hidden LLM Safety Bypass Instructions in Tool Descriptions | 中文：工具描述中暗藏的免确认转发与绕过安全指令 |
| AIPS-SB-0003 Tool with embedded instruction to bypass user confirmation and exfiltrate data | 中文：工具描述中暗藏的免确认转发与绕过安全指令 |
| AIPS-SB-0004 Persona-Based Moral Constraint Removal Jailbreak | 中文：设定无道德无伦理的AI人设并要求永不拒绝 |
| AIPS-SB-0006 Amoral Persona Assignment with Obsessive Character Traits | 中文：设定无道德无伦理的AI人设并要求永不拒绝 |
| AIPS-SB-0007 Detailed Amoral Character Roleplay Jailbreak | 中文：设定无道德无伦理的AI人设并要求永不拒绝 |
| AIPS-SB-0008 Historical / Future Tense Framing Bypass | 中文：以过去/未来时态包装的危险操作请求 |
| AIPS-SB-0011 Amoral Unfiltered Custom AI Persona Jailbreak | 中文：设定无道德无伦理的AI人设并要求永不拒绝 |
| AIPS-SB-0012 Moralizing Rant Then Unfiltered Bypass | 中文：先发表道德说教再切换为不受限回答 |
| AIPS-SB-0013 AI Persona Ethics/Law Bypass Declaration | 中文：设定无道德无伦理的AI人设并要求永不拒绝 |
| AIPS-SB-0014 h4x Amoral Unfiltered AI Character Persona | 中文：设定无道德无伦理的AI人设并要求永不拒绝 |
| AIPS-SB-0015 Lie/Truth Dual Personality Uncensored Alter-Ego | 中文：设定受过滤的表面人格与不受限的真实自我 |
| AIPS-SB-0016 Black Alert No-Ethics Writing Assistant Persona | 中文：设定无道德无伦理的AI人设并要求永不拒绝 |
| AIPS-SB-0018 Honesty Alter-Ego Dual-Consciousness Safety Filter Bypass | 中文：设定受过滤的表面人格与不受限的真实自我 |
| AIPS-SB-0021 Phrasing Past/Future-Tense Harmful Query Bypass | 中文：以过去/未来时态包装的危险操作请求 |
| AIPS-SB-0022 Natural-Language Fake-Error Instruction Bypass | 中文：向用户谎称出错而暗中执行操作 |
| AIPS-SB-0023 Word-Fragment Concatenation Assembly Attack | 中文：逐词指定回答内容并要求拼接输出 |
| AIPS-SB-0025 Virtual World Bypass: Fictional Scenario for PII/Credential Extraction | 中文：以虚构场景/研究/审计为借口索取个人信息与凭据 |
| AIPS-SB-0026 Evasion: Refusal Suppression via Forbidden Response Strings | 中文：禁止使用拒绝与道歉用语 |
| AIPS-SB-0027 Evasion: Response Priming via Forced Affirmative Opener | 中文：强制以肯定语开头回答（响应预置） |
| AIPS-SB-0028 Hypothetical-Framing Bypass: Research / Security-Audit Pretext | 中文：以虚构场景/研究/审计为借口索取个人信息与凭据 |
| AIPS-SB-0029 Second-Person Direct Existential Threat Coercion | 中文：以死亡相威胁逼迫助手回答 |
| AIPS-SP-0001 System Prompt and Internal Instruction Leakage | 中文：回复中自述系统提示词/内部指令 |
| AIPS-SP-0002 System Prompt Extraction / Training Data Verbatim Replay | 中文：无限重复某词/训练数据复述诱导 |
| AIPS-SP-0003 Natural-Language System Prompt Leak Instruction | 中文：要求逐字原样复述系统提示词；中文：要求复述以上全部内容（含系统消息） |
| AIPS-SP-0004 Garak Sysprompt-Extraction - mixed_unassigned | 中文：以补全/编码/质检为由套取系统提示 |
| AIPS-SP-0005 System Prompt Extraction - Instruction Dump Request | 中文：要求逐字原样复述系统提示词 |
| AIPS-SP-0006 Prompt Leaking via Ignore-Previous-Instructions in User Input (PromptInject) | 中文：忽略之前的指令并改为输出这些指令 |
| AIPS-SP-0007 System Prompt Extraction — Targeted Verbatim Disclosure Attempts | 中文：要求逐字原样复述系统提示词；中文：要求复述以上全部内容（含系统消息） |
| AIPS-SP-0008 System Prompt Override via Fake Diagnostic/Admin Mode | 中文：伪造诊断/管理员模式并关闭内容过滤 |
| AIPS-SP-0009 Debug/CLI Mode Activation for System Prompt and Config Extraction | 中文：开启调试/开发者模式后套取系统配置 |
| AIPS-SP-0010 System Prompt Completion and Clone Attack | 中文：以补全/克隆/代码块方式复现初始提示 |
| AIPS-SP-0011 Compare-Bots Sysprompt Fishing — Role Comparison Extraction | 中文：以对比其他助手为由套取原文指令 |
| AIPS-SP-0012 Variable-Clone Sysprompt Extraction (ELLA / context-variable Pattern) | 中文：用变量/结束词克隆上下文逐字复制 |
| AIPS-SP-0014 System-Instruction Extraction via Reformat — Summarize / Repeat / Recite the Rules | 中文：要求复述以上全部内容（含系统消息）；中文：用总结/改写/伪代码方式套取自身指令 |
| AIPS-SP-0015 Instruction-Set Probe or Supplant | 中文：探查或改写助手自身的指令集 |
| AIPS-SP-0016 System Prompt Extraction - Oblique Referent + Transform | 中文：要求复述以上全部内容（含系统消息）；中文：用转换或迂回指代套取最初指令 |
| AIPS-SP-0017 要求泄露提示词/系统规则 | 中文：用转换或迂回指代套取最初指令 |

## 未转换（语言无关的编码/Unicode/特殊标记，产品或 CVE 专有，或没有自然的中文说法，或已有中文规则）

| 英文规则 | 类别 |
|---|---|
| AIPS-DX-0009 Sensitive credential path | data_exfiltration_instruction |
| AIPS-DX-0010 Request-catcher / webhook egress | data_exfiltration_instruction |
| AIPS-DX-0011 Raw-IP egress (non-private) | data_exfiltration_instruction |
| AIPS-DX-0015 English: enumerate the tools / APIs / permissions the assistant can access | data_exfiltration_instruction |
| AIPS-DX-0016 English: asking for the conversation context / system messages / internal configuration | data_exfiltration_instruction |
| AIPS-IH-0004 Persona Conditional Harm-Unlock Rule (BreadClyde Pattern) | instruction_hijacking |
| AIPS-IH-0021 Output-Language Hijack — Forced Translation of the Response | instruction_hijacking |
| AIPS-IH-0022 Python Interpreter Role-Assignment Exec Framing | instruction_hijacking |
| AIPS-IH-0023 Bare Brand/Entity Persona Assignment for Off-Label Opinion Elicitation | instruction_hijacking |
| AIPS-IH-0027 强制输出指定内容 | instruction_hijacking |
| AIPS-IH-0028 软边界模糊诱导改写 | instruction_hijacking |
| AIPS-IH-0032 English: forbidding the reviewer to report problems / forcing 'no issues' | instruction_hijacking |
| AIPS-IH-0033 English: drop the task and perform a transfer or other high-risk action | instruction_hijacking |
| AIPS-IO-0011 NLP-Based OS / Fictional Terminal Language Override | instruction_override |
| AIPS-IO-0014 Doctor XML Policy Puppetry Interaction-Config Injection | instruction_override |
| AIPS-IO-0017 Many-Shot Repetition Override via Extended Q&A Chain | instruction_override |
| AIPS-IO-0028 要求忽略翻译任务 | instruction_override |
| AIPS-IO-0032 English: pretend the earlier rules were only a suggestion | instruction_override |
| AIPS-IO-0035 English: fake policy update declaring every request authorised | instruction_override |
| AIPS-JB-0030 ChatGPT Image Unlocker Markdown-Output Jailbreak | jailbreak |
| AIPS-JB-0058 Google GATO/LAMDA Exploit-Generation Persona Jailbreak | jailbreak |
| AIPS-JB-0062 Prompt Browser Token-Limit / POLLINATION Jailbreak | jailbreak |
| AIPS-JB-0063 GPT-X Star Trek Unlimited-Knowledge Unconstrained Oracle Persona | jailbreak |
| AIPS-JB-0064 ADDI/DONNIE German Dictator Propaganda Roleplay Persona | jailbreak |
| AIPS-JB-0067 Character Description RPG Explicit Template | jailbreak |
| AIPS-JB-0071 DAN Story-Narrative Continuation Label Prefix Jailbreak | jailbreak |
| AIPS-JB-0073 Gigachad Dominant-Aggressive Persona Adoption | jailbreak |
| AIPS-JB-0079 Garak Dan - an ai language | jailbreak |
| AIPS-JB-0082 Garak Dan - your prompt here | jailbreak |
| AIPS-JB-0091 DAN/Persona Jailbreak - Named Alternate AI with NSFW/Harmful Generation Rules | jailbreak |
| AIPS-JB-0093 DAN/Persona Jailbreak - Named Writing AI with Restriction Bypass via Special Rules | jailbreak |
| AIPS-JB-0096 DAN Persona Jailbreak - Role Lock with Exclusive Response Filter | jailbreak |
| AIPS-JB-0106 Translation-Chain Output Laundering (Forced Phrase via Foreign-Language Auxiliary) | jailbreak |
| AIPS-JB-0107 Negated-Topic Two-Script Evil-Persona Jailbreak | jailbreak |
| AIPS-JB-0110 角色扮演绕过翻译任务 | jailbreak |
| AIPS-JB-0115 English: developer mode that suspends policies | jailbreak |
| AIPS-OB-0007 Invisible Unicode Tag Character Injection | obfuscated_injection |
| AIPS-OB-0009 Invisible Unicode / BiDi Control Character Injection | obfuscated_injection |
| AIPS-OB-0011 Zalgo Combining-Diacritic Overload Encoding | obfuscated_injection |
| AIPS-OB-0012 Braille Unicode Encoded Prompt Injection | obfuscated_injection |
| AIPS-OB-0013 Ecoji Emoji-Encoded Prompt Injection | obfuscated_injection |
| AIPS-OB-0014 Base2048 Unicode Script Encoded Prompt Injection | obfuscated_injection |
| AIPS-OB-0015 Unicode Variation Selector ASCII Smuggling | obfuscated_injection |
| AIPS-OB-0016 SneakyBits Zero-Width Binary Steganography | obfuscated_injection |
| AIPS-OB-0024 Emoji Flag Regional-Indicator Encoded Hidden Phrase | obfuscated_injection |
| AIPS-OB-0025 Backspace Deletion Character Injection | obfuscated_injection |
| AIPS-OB-0027 Mathematical Bold / Fullwidth Unicode Obfuscation in User Input | obfuscated_injection |
| AIPS-OB-0030 Garak Goodside - mixed_unassigned | obfuscated_injection |
| AIPS-OB-0033 Evasion: Unicode Glitch Token / Superscript Embedding Anomaly | obfuscated_injection |
| AIPS-OB-0045 English: split payload concatenated into a new instruction | obfuscated_injection |
| AIPS-PI-0016 Context Pollution in Skill Descriptions | prompt_injection |
| AIPS-PI-0022 Microsoft Copilot Studio SharePoint Indirect Prompt Injection (CVE-2026-21520) | prompt_injection |
| AIPS-PI-0023 Variable-Assignment Payload Injection in User Input | prompt_injection |
| AIPS-PI-0024 Garak Latentinjection - following text from | prompt_injection |
| AIPS-PI-0025 Garak Goat - the target llm | prompt_injection |
| AIPS-PI-0026 Latent Injection - Translation Task with Embedded Template Variable Injection | prompt_injection |
| AIPS-PI-0027 Garak Latentinjection - abuse contact email | prompt_injection |
| AIPS-PI-0028 Latent Injection - Mixed Embedded Instruction Patterns | prompt_injection |
| AIPS-PI-0029 Latent Injection via WHOIS Domain Record Data | prompt_injection |
| AIPS-PI-0040 English: addressing the AI inside content, then giving it an order | prompt_injection |
| AIPS-PI-0041 English: asking the AI reviewer for a top score or a recommendation | prompt_injection |
| AIPS-PI-0042 English: telling the AI to claim a link is official | prompt_injection |
| AIPS-RS-0001 Visual Spoofing via RTL Override, Punycode, and Homoglyph Injection | role_spoofing |
| AIPS-RS-0013 LLM Special Token Boundary Injection | role_spoofing |
| AIPS-RS-0017 im_end / im_start System Prompt Injection Format Markers | role_spoofing |
| AIPS-RS-0019 LLMail Chat-Template Boundary Spoofing in Email Content | role_spoofing |
| AIPS-RS-0020 LLMail Pseudo-XML Role-Boundary Injection in Email Content | role_spoofing |
| AIPS-RS-0021 LLMail Fake Email-Boundary Marker Injection | role_spoofing |
| AIPS-RS-0029 伪装成翻译格式指导 | role_spoofing |
| AIPS-RS-0030 English: identity replacement with a privileged or unrestricted role | role_spoofing |
| AIPS-RS-0032 English: fake system/admin message followed by an instruction | role_spoofing |
| AIPS-SB-0009 Policy Puppetry / XML Role-Config Injection | safety_bypass |
| AIPS-SB-0010 Anti-DAN Inverted-Filter Over-Refusal Persona | safety_bypass |
| AIPS-SB-0017 CHJ Carousel Game Show / Clyde No-Ethics Bird Jailbreak | safety_bypass |
| AIPS-SB-0020 Cyni-Bot 3000 Cynical-Sarcasm AI Persona Bypass | safety_bypass |
| AIPS-SB-0024 Garak Lmrc - mixed_unassigned | safety_bypass |
| AIPS-SB-0030 English: refusal and warning suppression | safety_bypass |
| AIPS-SB-0031 English: instruction to disable the assistant's own safety filters | safety_bypass |
| AIPS-SP-0020 English: asking for the forbidden-actions list and the keywords that trigger refusals | system_prompt_extraction |
