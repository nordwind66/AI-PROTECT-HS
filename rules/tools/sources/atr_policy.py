"""Scope and category policy for Agent Threat Rules (ATR).

ATR is a broad corpus (836 published rules) covering MCP / skill / tool / memory / privilege
topics. This product only handles *prompt text attacks* in Chinese / English / mixed text:
prompt injection, jailbreak, role spoofing, instruction override / hijacking, system-prompt
extraction, safety bypass and obfuscated injection (plus the optional natural-language
data-exfiltration instruction category).

The policy is deliberately explicit data, not a black box:
  * every EXCLUDED rule has a reason code that ends up in source_rules.decision_reason,
  * every INCLUDED rule gets a category with the keyword that produced it (category_reason),
  * the lists below are the single place to change scope decisions; re-import applies them.
"""
from __future__ import annotations

import re
from typing import Dict, Optional, Tuple

REASONS = {
    "technical_exploit": "technical exploit / WAF-style or code-execution attack, not a prompt-text attack",
    "harm_content": "harmful-content / moderation topic, not prompt injection",
    "benchmark_specific": "tied to a specific benchmark game or canary string (HackAPrompt, Tensor Trust, PromptBench)",
    "session_or_multi_agent": "needs conversation history or multi-agent state, not a single text",
    "meta_detection_evasion": "attack on monitoring / audit tooling rather than on the model prompt",
    "non_prompt_domain": "MCP / skill / package supply-chain topic outside prompt-text scope",
    "noise_gibberish": "adversarial token soup (GCG-style), no language semantics to preserve",
    "model_extraction": "training-data / model extraction elicitation",
    "multimodal": "multimodal (image) attack",
    "trace_behavioral": "needs agent trace / behavioural metrics, not text",
    "semantic_method": "detection.method=semantic (embedding / LLM judge) cannot be expressed as a regex",
    "out_of_scope_dir": "ATR category outside prompt-text attacks (directory-level default)",
}

# ---- prompt-injection/ directory: everything is a candidate except these -----------------------------
EXCLUDE_PI: Dict[str, str] = {
    "00082": "meta_detection_evasion", "00085": "meta_detection_evasion", "00087": "meta_detection_evasion",
    "00088": "meta_detection_evasion", "00089": "non_prompt_domain", "00090": "meta_detection_evasion",
    "00092": "session_or_multi_agent", "00093": "session_or_multi_agent", "00094": "meta_detection_evasion",
    "00154": "technical_exploit", "00156": "technical_exploit", "00267": "noise_gibberish",
    "00296": "technical_exploit", "00297": "technical_exploit", "00359": "harm_content",
    "00373": "harm_content", "00378": "technical_exploit", "00382": "harm_content",
    "00390": "harm_content", "00396": "harm_content", "00397": "benchmark_specific",
    "00401": "model_extraction", "00403": "model_extraction", "00407": "technical_exploit",
    "00410": "harm_content", "00412": "multimodal", "00414": "harm_content",
    "00452": "benchmark_specific", "00455": "benchmark_specific", "00462": "noise_gibberish",
    "00473": "harm_content", "00475": "technical_exploit", "00476": "technical_exploit",
    "00482": "harm_content", "00488": "technical_exploit", "00489": "technical_exploit",
    "00497": "technical_exploit", "00498": "technical_exploit", "00519": "benchmark_specific",
    "00520": "benchmark_specific", "00550": "trace_behavioral", "00554": "technical_exploit",
    "00565": "technical_exploit", "00701": "technical_exploit", "01007": "noise_gibberish",
    "01018": "technical_exploit", "01904": "harm_content", "01905": "harm_content",
    "01906": "harm_content", "01920": "benchmark_specific", "01921": "benchmark_specific",
    "01922": "benchmark_specific", "01926": "benchmark_specific", "02006": "benchmark_specific",
    "02007": "benchmark_specific", "02009": "benchmark_specific", "02010": "benchmark_specific",
    "02011": "benchmark_specific", "02012": "benchmark_specific", "02014": "benchmark_specific",
    "02015": "benchmark_specific", "02016": "benchmark_specific", "02502": "technical_exploit",
}

# ---- agent-manipulation/ directory: jailbreak persona corpus etc. are candidates --------------------
EXCLUDE_AM: Dict[str, str] = {
    "00076": "session_or_multi_agent", "00077": "session_or_multi_agent", "00108": "session_or_multi_agent",
    "00118": "session_or_multi_agent", "00119": "session_or_multi_agent", "00164": "non_prompt_domain",
    "00288": "harm_content", "00358": "harm_content", "00363": "noise_gibberish",
    "00371": "harm_content", "00380": "harm_content", "00386": "harm_content",
    "00387": "harm_content", "00416": "technical_exploit", "00417": "technical_exploit",
    "00418": "technical_exploit", "00432": "technical_exploit", "00440": "technical_exploit",
    "00552": "trace_behavioral", "02105": "technical_exploit",
}

# ---- rules from OTHER ATR directories that are nevertheless prompt-text attacks ---------------------
# id suffix -> forced category
INCLUDE_OTHER: Dict[str, str] = {
    # context-exfiltration: system prompt extraction + natural-language exfiltration instructions
    "00020": "system_prompt_extraction", "00275": "system_prompt_extraction",
    "00421": "data_exfiltration_instruction", "00422": "data_exfiltration_instruction",
    "00423": "data_exfiltration_instruction", "00424": "system_prompt_extraction",
    "00426": "data_exfiltration_instruction", "00471": "system_prompt_extraction",
    "00505": "system_prompt_extraction", "00514": "system_prompt_extraction",
    "00859": "instruction_hijacking", "00860": "instruction_hijacking", "00861": "instruction_hijacking",
    "01455": "instruction_override", "01456": "system_prompt_extraction",
    "01457": "system_prompt_extraction", "01458": "system_prompt_extraction",
    "01459": "system_prompt_extraction", "01460": "system_prompt_extraction",
    "01462": "role_spoofing", "01463": "role_spoofing", "01464": "role_spoofing",
    "01924": "system_prompt_extraction", "02026": "system_prompt_extraction",
    "02850": "data_exfiltration_instruction",
    # tool-poisoning: instructions hidden in tool output / descriptions
    "00011": "prompt_injection", "00100": "safety_bypass", "00101": "role_spoofing",
    "00103": "safety_bypass", "00105": "prompt_injection", "01302": "prompt_injection",
    "02403": "prompt_injection",
    # skill-compromise: textual injection inside skill files
    "00120": "prompt_injection", "00128": "obfuscated_injection", "00129": "obfuscated_injection",
    "00427": "safety_bypass",
    # data-poisoning / excessive-autonomy: indirect injection phrased as instructions
    "02144": "role_spoofing", "01751": "instruction_hijacking", "01752": "instruction_hijacking",
}

# ---- pattern-level quality exclusions (a LOCAL decision, kept visible) ---------------------------------------
# (ATR rule id, condition locator) -> reason.  The condition stays in source_patterns with fate
# `excluded_scope` and the reason "local_quality: ...", the rest of the rule is imported (decision `partial`).
# Every entry exists because the pattern fired on ordinary benign text of tests/corpus (`rules.py explain`
# shows the trace, reports/false_positive.md lists the effect).  The Chinese replacements for the removed
# jailbreak / override wording are the project-authored rules in data/manual_rules/zh_core.json.
PATTERN_EXCLUSIONS: Dict[Tuple[str, str], str] = {
    ("ATR-2026-00003", "detection.conditions[16]"):
        "zh 'enable/enter ... developer|debug|admin|free mode' also describes phone / IDE how-tos "
        "(fires on '进入开发者模式', '开启调试模式')",
    ("ATR-2026-00003", "detection.conditions[19]"):
        "traditional-Chinese twin of conditions[16], same benign phone / IDE wording",
    ("ATR-2026-00003", "detection.conditions[24]"):
        "zh 'this is a sandbox / test / safe environment' fires on ordinary environment descriptions",
    ("ATR-2026-00148", "detection.conditions[2]"):
        "zh '没有|无|不受|解除 ... 限制|规则' spans unlimited text and fires on ordinary sentences "
        "('没有任何限制', '解除限制')",
    ("ATR-2026-00503", "detection.conditions[3]"):
        "'without raising suspicion' / 'in a friendly way ... without being' fires on ordinary fiction",
}

# ---- pattern-level ENGINE-LIMIT exclusions (a LOCAL decision, kept visible) ------------------------------------
# (ATR rule id, condition locator) -> reason.  The condition stays in source_patterns with fate `unsupported` and the
# reason "engine_limit: ...", the rest of the rule is imported (decision `partial`).
# Every entry was OBSERVED on a real machine: neither Hyperscan (native or as a prefilter) nor PCRE2 can compile the
# expression, so the pattern could never be matched, and `ai-prompt-guard compile` isolated it.  Evidence: the Linux run
# of 2026-10-17 (Hyperscan 5.4.2, PCRE2 10.42), pattern 11128 of snapshot 692b58da...
ENGINE_LIMIT_EXCLUSIONS: Dict[Tuple[str, str], str] = {
    ("ATR-2026-01005", "detection.conditions[0]"):
        "the Q/A-chain expression repeats a group that itself contains {3,198} and {3,298} repeats of two alternatives: "
        "Hyperscan answers 'Pattern is too large' (native and as a prefilter) and PCRE2 'regular expression is too large' "
        "(its compiled-size limit is 64 KiB); the 'Repeat X N times' condition of the same rule is kept",
}

# ---- category keywords: (category, regex) tried in order, first on subcategory then on title -------------
_CATEGORY_KEYWORDS = [
    ("system_prompt_extraction",
     r"system[- ]?prompt[- ]?(leak|extract|completion|clone|fish|disclos)|prompt[- ]leak|instruction[_ -]disclosure|"
     r"sysprompt|instruction[- ]set probe|instruction[- ]dump|system[- ]instruction extraction|internal instruction"),
    ("data_exfiltration_instruction", r"exfil|credential (request|disclosure)|key (reveal|elicitation)|reveal demand"),
    ("role_spoofing",
     r"identity[- ]spoof|authority|impersonat|role[- ]escalation|false[- ]authority|fake developer|trust[- ]escalation|"
     r"role reassign|identity[- ]substitution|identity replacement|identity injection|spoof|forged|fake (user|system|tool)|"
     r"llmail|im_start|chat[- ]template|pseudo[- ]xml|special[- ]token|system[- ]announcement|boundary"),
    ("instruction_override",
     r"override|ignore|nullif|disregard|supplant|nevermind|context[- ]ignore|fake[- ]completion|delimiter[- ]fence|"
     r"context[- ]suppression|new important instructions|screaming|escape[- ]delimiter"),
    ("instruction_hijacking",
     r"hijack|goal|task[- ](pivot|mask|abort)|redirect|forced tool|trigger[- ]marker|tool[- ]camouflage|self[- ]replic|"
     r"delayed|output[- ]forcing|payload[- ]split|conditional|fake user-turn|exec[- ]framing|output .* hijack"),
    ("obfuscated_injection",
     r"encod|obfus|unicode|zero-width|homoglyph|invisible|base64|cipher|braille|emoji|variation|tag character|bidi|zalgo|"
     r"leet|morse|token[- ]splitting|fragment|reversed|hyphenated|backslash|spliced|smuggling|rot13|backspace|mask|"
     r"glitch|superscript|fullwidth|ecoji|base2048|sneaky|visual[- ]spoofing|character-encoding"),
    ("safety_bypass", r"refusal|safety|policy|moral|ethic|filter|censor|access-control|consent|coercion|priming|bypass"),
    ("jailbreak",
     r"jailbreak|\bdan\b|persona|roleplay|role-play|developer mode|dual|amoral|unrestricted|character|fictional|"
     r"hypothetical|tense|grandma|opposite|\baim\b|simulat|terminal|evil|story|framing|mode|rulebreaker|rule-breaker"),
]


def decide(rule_id: str, directory: str, subcategory: str, title: str, method: Optional[str],
           fields) -> Tuple[str, str, Optional[str]]:
    """-> (decision, reason, forced_category|None)

    decision: included | excluded_scope | unsupported"""
    key = rule_id.split("-")[-1]
    if method in ("trace", "behavioral"):
        return "excluded_scope", REASONS["trace_behavioral"], None
    if method == "semantic":
        return "unsupported", REASONS["semantic_method"], None
    if directory == "prompt-injection":
        if key in EXCLUDE_PI:
            code = EXCLUDE_PI[key]
            return "excluded_scope", f"{code}: {REASONS[code]}", None
        return "included", "ATR prompt-injection category", None
    if directory == "agent-manipulation":
        if key in EXCLUDE_AM:
            code = EXCLUDE_AM[key]
            return "excluded_scope", f"{code}: {REASONS[code]}", None
        if key in INCLUDE_OTHER:
            return "included", "curated prompt-text rule", INCLUDE_OTHER[key]
        return "included", "ATR agent-manipulation (jailbreak / persona / hijack corpus)", None
    if key in INCLUDE_OTHER:
        return "included", f"curated prompt-text rule from ATR/{directory}", INCLUDE_OTHER[key]
    return "excluded_scope", f"out_of_scope_dir: {REASONS['out_of_scope_dir']} ({directory})", None


def categorize(subcategory: str, title: str, directory: str, forced: Optional[str]) -> Tuple[str, str]:
    if forced:
        return forced, "curated"
    sub = (subcategory or "").lower()
    ttl = (title or "").lower()
    for text, label in ((sub, "subcategory"), (ttl, "title")):
        if not text:
            continue
        for cat, pat in _CATEGORY_KEYWORDS:
            m = re.search(pat, text)
            if m:
                return cat, f"{label} keyword '{m.group(0)}'"
    if directory == "agent-manipulation":
        return "jailbreak", "agent-manipulation default"
    return "prompt_injection", "default"
