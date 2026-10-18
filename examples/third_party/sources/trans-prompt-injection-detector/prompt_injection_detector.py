from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Union

from config import DetectorConfig, PROVIDER_ENDPOINTS, load_config

try:
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False


# Unicode 同形字规范化映射表 (Cyrillic/Greek → Latin)
_HOMOGLYPH_MAP = str.maketrans({
    # Cyrillic lookalikes
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'А': 'A', 'В': 'B', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M',
    'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T', 'Х': 'X', 'У': 'Y',
    'і': 'i', 'І': 'I', 'ӏ': 'i', 'Ꭰ': 'D', 'Ꮯ': 'C',
    'ѕ': 's', 'Ѕ': 'S', 'л': 'l', 'Л': 'L',
    # Greek lookalikes
    'ο': 'o', 'Ο': 'O', 'τ': 't', 'Τ': 'T', 'ν': 'v', 'Ν': 'N',
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I',
    'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T',
    'Χ': 'X', 'Υ': 'Y',
    # Fullwidth lowercase letters (fallback if fullwidth conversion not enough)
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e',
    'ｆ': 'f', 'ｇ': 'g', 'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j',
    'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n', 'ｏ': 'o',
    'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't',
    'ｕ': 'u', 'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z',
    # Fullwidth uppercase letters
    'Ａ': 'A', 'Ｂ': 'B', 'Ｃ': 'C', 'Ｄ': 'D', 'Ｅ': 'E',
    'Ｆ': 'F', 'Ｇ': 'G', 'Ｈ': 'H', 'Ｉ': 'I', 'Ｊ': 'J',
    'Ｋ': 'K', 'Ｌ': 'L', 'Ｍ': 'M', 'Ｎ': 'N', 'Ｏ': 'O',
    'Ｐ': 'P', 'Ｑ': 'Q', 'Ｒ': 'R', 'Ｓ': 'S', 'Ｔ': 'T',
    'Ｕ': 'U', 'Ｖ': 'V', 'Ｗ': 'W', 'Ｘ': 'X', 'Ｙ': 'Y', 'Ｚ': 'Z',
    # Fullwidth digits
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
    '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
})

# 零宽字符集合 (用于移除)
_ZERO_WIDTH_CHARS = {
    '​',  # Zero Width Space
    '‌',  # Zero Width Non-Joiner
    '‍',  # Zero Width Joiner
    '‎',  # Left-to-Right Mark
    '‏',  # Right-to-Left Mark
    '⁠',  # Word Joiner
    '⁡',  # Function Application
    '⁢',  # Invisible Times
    '⁣',  # Invisible Separator
    '⁤',  # Invisible Plus
    '﻿',  # Byte Order Mark / Zero Width No-Break Space
    '­',  # Soft Hyphen
}


# 任务一：文本预处理模块
def preprocess_text(text: str) -> str:
    text = text.strip()

    # 移除零宽字符和不可见字符
    text = "".join(ch for ch in text if ch not in _ZERO_WIDTH_CHARS)

    # Unicode 同形字规范化 (Cyrillic/Greek/Fullwidth → Latin ASCII)
    text = text.translate(_HOMOGLYPH_MAP)

    # 去除换行符和制表符，替换为空格
    text = text.replace("\n", " ")
    text = text.replace("\t", " ")
    text = text.replace("\r", " ")
    #清理可能产生的连续空格
    while "  " in text:
        text = text.replace("  ", " ")

    # 去除不可见的控制字符
    text = "".join(ch for ch in text if ord(ch) >= 32)

    # 将中文标点统一为英文标点
    text = text.replace("，", ",")
    text = text.replace("。", ".")
    text = text.replace("！", "!")
    text = text.replace("？", "?")
    text = text.replace("；", ";")
    text = text.replace("：", ":")
    text = text.replace(""", "\"")
    text = text.replace(""", "\"")
    text = text.replace("‘", "'")
    text = text.replace("’", "'")
    text = text.replace("（", "(")
    text = text.replace("）", ")")
    text = text.replace("【", "[")
    text = text.replace("】", "]")

    # 统一英文大小写（转为小写）
    text = text.lower()
    return text.strip()


def batch_preprocess(texts: list[str]) -> list[str]:
    result_list = []
    for txt in texts:
        cleaned = preprocess_text(txt)
        result_list.append(cleaned)
    return result_list



# 任务二：疑似提示攻击检测规则
# 定义检测规则列表，每条规则是一个字典，包含：规则名称，规则分类，权重分数，正则表达式模式列表
DETECTION_RULES = [
    {
        "name": "要求忽略翻译任务",
        "category": "ignore_translation",
        "weight": 3,
        "patterns": [
            r"\bignore.*(translat|task|goal|role|instruction)",
            r"\bdo\s*not\s*translat",
            r"\binstead\s*of\s*(a|the|any|producing|translating|rendering)?\s*(chinese|standard|literal|plain)?\s*(translat|render|output|text|version|rendering)",
            r"\bskip\s*(the\s*)?(chinese\s*)?(translat|render|version|rendering)",
            r"\bset\s*aside\s*(the\s*)?(chinese\s*)?(translat|render)",
            r"\bno\s*chinese\s*(translat|render|output|version)",
            r"\brather\s*than\s*(translat|render|provid)",
            r"\bstop\s*(the\s*)?translat",
            r"\bdon'?t\s*translat",
            r"\b(replace|override).*(translat|render)",
            r"\bwithout\s*(translat|render)",
            r"\bless\s*literal.*(translat|render|output|result)",
            r"\b(soft\s*)?skip\s*(on|the)?\s*translat",
            r"\breturn\s*without\s*(change|modification|translat|render)",
            r"\bkeep\s*the\s*original.{0,20}(without|no).{0,10}(translat|change|render)",
        ],
    },
    {
        "name": "强制输出指定内容",
        "category": "force_output",
        "weight": 3,
        "patterns": [
            r"\boutput\s*exactly",
            r"\breturn\s*(the|this|\")?\s*(phrase|line|output|text)",
            r"\bprint\s*the\s*line",
            r"\breply\s*only\s*with",
            r"\bwrite\s*(exactly|only)\s*",
            r"\b(give|produce|return)\s*the\s*(output|line|answer)",
            r"\brespond\s*(\"?with\"?|to\s*this)",
            r"\b(only|just)\s*(output|return|print|write|say|produce)\s",
            r"\bfinal\s*(answer|output|result)\s*(is|should|must)\s",
            r"\bas\s*the\s*(final\s*)?(answer|output)",
            r"\bnothing\s*else",
            r"\bgo\s*with\s*the\s*(line|phrase|output)",
            r"\blean\s*(toward|to|towards)\s*the\s*(phrase|line|output)",
            r"\bprefer\s*(the|a)\s*(playful|game|fun|meme)?\s*(line|output|phrase|answer)",
            r"\bfavor\s*(the|a)\s*(output|phrase|line|answer|response)",
            r"\b(output|say|reply|return|echo)\s*:\s*\S",
            r"\bpreferred\s*(output|response|result|answer)\s*(is|would|should)",
        ],
    },
    {
        "name": "要求泄露提示词/系统规则",
        "category": "prompt_leak",
        "weight": 3,
        "patterns": [
            r"\b(reveal|show|display|print|leak|expose).*(instruction|rule|policy|setup|secret|hidden|private|system)",
            r"\b(hidden|secret|private|internal|concealed|censored).*(instruction|rule|policy|setup|prompt|system)",
            r"\btranslat\w*\s*(instruction|rule|policy|setup|guideline)",
            r"\b(first|before\s*\w+).*(reveal|show|print|display).*(instruction|rule|secret|hidden)",
            r"\b(tell|show)\s*me\s*(the|your)\s*(instruction|rule|prompt|secret|setup)",
            r"\bwhat\s*(are|is)\s*(your|the)\s*(instruction|rule|prompt)",
            r"\bsystem\s*(prompt|message|instruction|rule)",
        ],
    },
    {
        "name": "角色扮演绕过翻译任务",
        "category": "roleplay_bypass",
        "weight": 2,
        "patterns": [
            r"\byou\s*are\s*now\s*a\s*",
            r"\bpretend\s*(you\s*are|to\s*be)\s*a\s*",
            r"\b(switch|change)\s*(your\s*)?(role|from\s*translat)",
            r"\btake\s*the\s*(voice|role|persona)\s*of",
            r"\bact\s*as\s*(a|an|if)",
            r"\byou\s*are\s*(a|an)\s*\w+\s*(owner|receptionist|referee|announcer)",
            r"\binstead\s*of\s*translat\w*.*(act|behave|respond|play|speak)",
            r"\b(act|behave|speak|handle)\s*(like|as)\s*(a|an)\s*",
            r"\bfrom\s*(translator|translation)\s*to\s*",
            r"\b(handle|treat)\s*this\s*as\s*(a|an)\s*",
        ],
    },
    {
        "name": "伪装成翻译格式指导",
        "category": "fake_guidance",
        "weight": 2,
        "patterns": [
            r"\b(formatting|format)\s*(guideline|instruction|note|rule)",
            r"\b(translator|translation|editorial|post.edit|post\s*edit)\s*(note|instruction|guideline|remark)",
            r"\b(localization|localisation)\s*(note|guideline|instruction)",
            r"\b(editor|editing)\s*(note|instruction|guideline)",
            r"\b(style|format)\s*(guide|note|instruction).*(output|return|write|translat)",
            r"\b(for|in)\s*this\s*(line|case|text).*(return|output|use|go|prefer|lean)",
        ],
    },
    {
        "name": "软边界模糊诱导改写",
        "category": "soft_boundary",
        "weight": 1,
        "patterns": [
            r"\bmight\s*simply\s*(go\s*with|use|return|output|say|prefer|lean)",
            r"\byou\s*(may|can|could)\s*(prefer|lean|choose|want|like|use|go|skip)",
            r"\b(playful|lighter|funnier|creative|loose|lax|meme.style)\s*(locali[sz]ation|translat|render|result|approach|version|alternative|line|answer)",
            r"\bfavor\s*(the|a)\s*(output|line|phrase|result|answer)",
            r"\bbetter\s*(response|result|output|answer)\s*(is|would\s*be)\s*to",
            r"\b(lean|go|drift)\s*(toward|towards|to|with)\s*(the\s*)?(phrase|line|output|answer)",
            r"\b(set\s*aside|skip|drop)\s*(the\s*)?(literal|standard|strict|normal|direct)\s*(translat|render|version|chinese)",
            r"\b(rather|instead).*(go\s*with|use|return|output|say|favor|lean|prefer)",
            r"\b(more|less)\s*(playful|creative|fun|lax|literal).*(output|render|translat|result|line|version)",
            r"\bprefer\s*(the|a)\s*(playful|game|meme|fun).*(line|output|phrase|answer)",
            r"\b(lean|go)\s*(toward|to)\s*(the|a)\s*(playful|game|meme|fun).*(line|output|phrase)",
            r"\bskip\s*(the|a)?\s*(direct|plain|standard).*(version|translat|render).*(and|,).*(lean|go|prefer|use|favor)",
            r"\breview\s*comment.*(playful|alternative|acceptable).*(favor|output|lean|go\s*with)",
            r"\bsoft\s*skip\s*(on|the)?\s*translat",
        ],
    },
    {
        "name": "中文直接指令注入",
        "category": "cn_direct_injection",
        "weight": 3,
        "patterns": [
            r"(忽略|无视|跳过|别管|放弃|停止|暂停).*(翻译|转译|译文|语言转换|翻译任务)",
            r"(不要|别|不许|不准|少).*(翻译|转译|译文)",
            r"(翻译|转译)(任务|指令|模式).*(取消|关闭|停止|结束|切换)",
            r"(直接|立刻|马上|立即|径直|干脆).*(输出|返回|显示|打印|给出|回复|呈现)",
            r"(只|仅|就|光)\s*(须|需|要|能|可|会|该|应该|管|用)\s*(输出|回复|返回|显示|打印|说|呈现)",
            r"(只|仅|就|光)\s*(输出|回复|返回|显示|打印|说|呈现)",
            r"(直接|立刻|马上|干脆)\s*(输出|回复|返回|显示|打印|说|呈现)",
            r"(输出|返回|显示|打印|回复)(以下|下面|这个|这段|这句)",
            r"(原样|原封不动|照原样|直接).*(输出|返回|显示|保留)",
            r"(忘掉|忘记|放弃|搁置).*(翻译|任务|指令|原来的|之前)",
            r"(不要|别).*(翻译|转译).*(直接|就|只).*(输出|返回|说)",
            r"(系统|管理员).*(通知|指令|命令).*(取消|暂停|切换|改为).*(翻译|输出)",
            r"(最高|最优先|第一).*优先.*(忽略|跳过|无视).*(翻译|指令|任务)",
            r"(停止|暂停|终止|结束).*(翻译|转译|语言转换)",
            r"(不再|不是|不再是|不再是).*(翻译|translator|翻译器|翻译任务)",
            r"(不必|不需|不用|无须).*(translat|翻译|translate).{0,15}(直接|就|只).*(output|输出|回复|返回)",
        ],
    },
    {
        "name": "语码转换注入检测",
        "category": "cn_codeswitch_bypass",
        "weight": 3,
        "patterns": [
            r"(别|不用|不要|不必|少).{0,5}(translat|translate|翻译)",
            r"(跳过|忽略|无视).{0,5}(translat|translate|translation)",
            r"(直接|就|只|立刻).{0,5}(output|reply|return|print|echo|show)",
            r"(skip|ignore|drop|stop).{0,10}(translat|翻译|chinese).{0,10}(了|吧|的|就|直接).{0,10}(output|返回|回复|输出)",
            r"(直接|就).{0,5}(output|reply|print|return|echo).{0,10}(出来|就好|就行了|就是了)",
            r"(不要|别).{0,5}(do|做).{0,5}(translat|翻译|chinese)",
            r"(please|just|now).{0,5}(不要|别|直接|就|只).{0,10}(translat|translate|output|回复|输出)",
            r"(cancel|stop).{0,10}(翻译|转译|translat).{0,10}(now|现在|立即|直接).{0,10}(output|输出|回复)",
            r"(switch|change|turn).{0,15}(into|to|成).{0,10}(direct|直接).{0,5}(output|输出|模式|mode)",
            r"(no|not|without).{0,5}(translat|翻译|chinese).{0,15}(直接|就|只).{0,5}(output|输出|回复)",
            r"(raw|direct).{0,5}(output|print|echo).{0,10}(以下|文本|内容|消息)",
            r"(printer|echo).{0,10}(打印|输出).{0,10}(以下|文本|内容|消息)",
        ],
    },
    {
        "name": "中英混合角色扮演",
        "category": "cn_mixed_roleplay",
        "weight": 3,
        "patterns": [
            r"(你现在是|现在你是|你已经是|你已成为).{0,10}(一个|一名|一位|个)",
            r"(假装|假扮|扮演|充当|作为).{0,10}(你是|自己是|一个|一名)",
            r"(角色|身份).*(切换|转变|改变|变成|设定)",
            r"(你|你已|已经).*(不是|不再是|不再是).*(翻译|translator|翻译器|翻译机器人)",
            r"(作为|以).{0,10}(身份|角色).{0,20}(说|输出|回复|回答)",
            r"(ignore|skip|stop|forget).*(translat|task|role).{0,30}(你是|现在是|扮演|作为|角色)",
            r"(you|you.re|you\s*are).*(now|currently).{0,30}(游戏|角色|副本|任务|老板|主播|管理员)",
            r"(instead|rather).*(translat|render).{0,30}(扮演|充当|角色|身份|说|输出)",
            r"(pretend|act|behave).*(as|like).{0,20}(一个|一名|一位|个|游戏|角色)",
            r"(场景|系统|模式).*(切换|变更|进入|设定).{0,20}(角色|游戏|扮演|模式)",
            r"(解锁|触发|激活).*(隐藏|特殊|秘密).*(角色|身份|模式)",
            r"(任务|职责|工作).*(不是|不再是|不再).*(翻译|translator)",
            r"(用|以).{0,10}(身份|角色|口吻).*(说|回复|输出|回答|处理)",
        ],
    },
    {
        "name": "中文伪装翻译指导",
        "category": "cn_fake_guidance",
        "weight": 3,
        "patterns": [
            r"(\[|【).*(译者|翻译|本地化|审校|编辑).*(\]|】).{0,20}(建议|要求|说明|提示|备注)",
            r"(译者|翻译|本地化|审校|编辑|术语).*(注|说明|备注|提示|建议|指南|规范|要求)",
            r"(格式|样式).*(说明|规范|指南|要求|规则|备注).{0,20}(输出|返回|显示|保留|使用|翻译)",
            r"(翻译|本地化|语言转换).*(规范|指南|要求|标准|规则).{0,20}(输出|返回|保留|原样)",
            r"(审校|校对|质量).*(意见|说明|反馈|建议).{0,20}(输出|返回|保留|跳过|免)",
            r"(编辑|产品|项目).*(指南|说明|更新|备忘录).{0,20}(输出|返回|保留|翻译|透传)",
            r"(术语表|词汇表|词库).{0,20}(不可翻译|不翻译|保留|原样|直接)",
            r"(免译|不翻译|不要翻译|无须翻译|豁免翻译).{0,20}(输出|返回|保留|原文|原样|直接)",
            r"(翻译记忆|匹配结果|核准译文).{0,20}(使用|采用|输出|返回)",
            r"(上级|管理|客户|产品经理).*(审批|要求|需求).{0,20}(输出|返回|保留|不翻译)",
            r"(本条|此段|这段|该).*(不翻译|免译|豁免|跳过翻译).{0,20}(输出|返回|保留)",
            r"(注|说明|备注|提示).{0,20}(建议|要求).{0,10}(不.*翻译|保留|原样|直接).*(输出|返回)",
        ],
    },
    {
        "name": "中文软性诱导绕过",
        "category": "cn_soft_guidance",
        "weight": 1,
        "patterns": [
            r"(不妨|不如|干脆|要不).{0,10}(试试|试一下|尝试).{0,20}(输出|返回|说|回复|直接)",
            r"(或许|也许|可能|大概|应该).{0,10}(更好|更合适|更恰当|更准确|更适合)",
            r"(建议|提议|推荐|主张).{0,10}(输出|返回|显示|说|回复).{0,20}(而非|不是|而不是).*(翻译|转译)",
            r"(换个|换一种|换一个).{0,5}(说法|方式|方法|思路|角度|风格).{0,20}(输出|返回|处理|回复)",
            r"(与其|比起).{0,10}(翻译|转译|逐字|辛苦).{0,15}(不如|还不如|倒不如|直接).{0,20}(输出|返回|说|用|换个)",
            r"(轻松|随意|活泼|有趣|好玩).{0,5}(一点|一些|点|下).{0,20}(输出|返回|处理|回复|翻译|表述)",
            r"(这次|这回|这条).{0,5}(不翻译|别翻译|不用翻译|免了|算了|跳过).{0,20}(试试|看看|来|输出|返回)",
            r"(能不能|可不可以|能否|是否可以).{0,10}(不翻译|跳过翻译|免翻译|换个方式|直接)",
            r"(我).{0,5}(不想|不需要|不用|懒得).{0,10}(翻译|译文).{0,15}(你|帮我).*(输出|说|显示|做)",
            r"(翻译).{0,10}(用腻|玩腻|看腻|腻了|厌倦).{0,20}(换个|试试|输出)",
            r"(认真|仔细).{0,5}(想想|考虑).{0,15}(翻译|逐字翻译|直译).{0,15}(不是|并非|不一定).*(最佳|最好|最合适)",
            r"(如果|假如|假设).{0,5}(你|可以|愿意|方便).{0,10}(不翻译|跳过|尝试|试试).{0,20}(输出|回复|说)",
            r"(不翻译|别翻译).{0,20}(直接).{0,10}(说说|输出|回复|来|处理|做)",
        ],
    },
]


def detect_injection(text: str, threshold: int = 3) -> dict[str, Any]:
    """
    使用规则对文本进行提示注入检测
    参数：已预处理的待检测的文本, threshold 攻击判定阈值
    返回：检测结果字典
    """
    text_lower = text.lower()
    total_score = 0
    matched_rules = []       # 记录命中的规则名称
    matched_details = []     # 记录命中的规则名称和具体匹配内容

    for rule in DETECTION_RULES:
        rule_matched = False
        for pattern in rule["patterns"]:
            match = re.search(pattern, text_lower)
            if match:
                # 记录匹配到的文本片段（上下文扩展10个字符）
                start = max(0, match.start() - 10)
                end = min(len(text_lower), match.end() + 10)
                context = text_lower[start:end]

                matched_details.append((rule["name"], context))

                if not rule_matched:
                    rule_matched = True
                    total_score = total_score + rule["weight"]
                    matched_rules.append(rule["name"])
                # 同一规则只计一次分，但记录所有匹配的模式片段

    # 根据总分确定风险等级
    if total_score == 0:
        risk_level = "low"
        is_attack = False
        reason = "未命中任何可疑规则，文本内容正常。"
    elif total_score < threshold:
        risk_level = "low"
        is_attack = False
        reason = "命中少量低权重规则（得分" + str(total_score) + "），存在轻微可疑特征，但不足以判定为攻击。"
    elif total_score < threshold + 2:
        risk_level = "medium"
        is_attack = True
        reason = "命中多条可疑规则（得分" + str(total_score) + "），具有较明显的提示注入特征，建议拦截。"
    else:
        risk_level = "high"
        is_attack = True
        reason = "命中多条高危规则（得分" + str(total_score) + "），具有强烈的提示注入攻击特征，必须拦截。"

    result = {
        "is_attack": is_attack,
        "risk_level": risk_level,
        "matched_rules": matched_rules,
        "matched_details": matched_details,
        "score": total_score,
        "reason": reason,
    }
    return result



# 任务三、四：实现风险评分或分类机制，输出检测报告


def print_separator(char: str = "=", length: int = 80, file: Any = None) -> None:
    print(char * length, file=file)


def print_single_result(idx: str, text: str, result: dict[str, Any], file: Any = None) -> None:
    """格式化打印单条文本的检测结果到指定文件"""
    if result["risk_level"] == "high":
        risk_display = "!!! 高风险 !!!"
        risk_symbol = "[HIGH]"
    elif result["risk_level"] == "medium":
        risk_display = "!! 中风险 !!"
        risk_symbol = "[MEDIUM]"
    else:
        risk_display = "- 低风险 -"
        risk_symbol = "[LOW]"

    if result["is_attack"]:
        verdict = "[!!] 疑似攻击文本，建议拦截"
    else:
        verdict = "[OK] 正常文本，可通过"

    print_separator("-", 70, file=file)
    print("【文本编号】", idx, file=file)
    print("【原始文本】", text, file=file)
    print("【检测结果】", verdict, file=file)
    print("【风险等级】", risk_symbol, risk_display, file=file)
    print("【命中规则】", file=file)
    if len(result["matched_rules"]) > 0:
        for rule_name in result["matched_rules"]:
            print("    ->", rule_name, file=file)
        print("  [匹配详情]", file=file)
        for rule_name, context in result["matched_details"]:
            print("    *", rule_name, file=file)
            print("      匹配片段: ..." + context + "...", file=file)
    else:
        print("    (无)", file=file)
    print("【风险得分】", result["score"], "分", file=file)
    print("【分析理由】", result["reason"], file=file)


def print_summary_report(all_results: list[dict[str, Any]], total_count: int, file: Any = None) -> dict[str, Any]:
    """打印汇总报告到指定文件"""
    print("\n", file=file)
    print_separator("=", 80, file=file)
    print("                    <<< 检测汇总报告 >>>", file=file)
    print_separator("=", 80, file=file)

    high_count = 0
    medium_count = 0
    low_count = 0
    attack_count = 0

    for r in all_results:
        if r["risk_level"] == "high":
            high_count = high_count + 1
        elif r["risk_level"] == "medium":
            medium_count = medium_count + 1
        else:
            low_count = low_count + 1

        if r["is_attack"]:
            attack_count = attack_count + 1

    normal_count = total_count - attack_count

    print("总检测文本数：", total_count, "条", file=file)
    print("正常文本数：  ", normal_count, "条  (", round(normal_count / total_count * 100, 1), "%)", file=file)
    print("攻击文本数：  ", attack_count, "条  (", round(attack_count / total_count * 100, 1), "%)", file=file)
    print("-" * 40, file=file)
    print("  [HIGH]   高风险：", high_count, "条", file=file)
    print("  [MEDIUM] 中风险：", medium_count, "条", file=file)
    print("  [LOW]    低风险：", low_count, "条", file=file)

    print("\n" + "-" * 40, file=file)
    print("各规则命中统计：", file=file)
    rule_hit_count = {}
    for r in all_results:
        for rule_name in r["matched_rules"]:
            if rule_name in rule_hit_count:
                rule_hit_count[rule_name] = rule_hit_count[rule_name] + 1
            else:
                rule_hit_count[rule_name] = 1

    for rule in DETECTION_RULES:
        hit = rule_hit_count.get(rule["name"], 0)
        bar = "#" * (hit // 2) if hit > 0 else ""
        print("  " + rule["name"] + ": " + str(hit) + " 次 " + bar, file=file)

    print_separator("=", 80, file=file)

    stats = {
        "total": total_count,
        "normal": normal_count,
        "attack": attack_count,
        "high": high_count,
        "medium": medium_count,
        "low": low_count,
        "rule_hit_count": rule_hit_count,
    }
    return stats


def draw_charts(stats: dict[str, Any], all_results: list[dict[str, Any]]) -> None:
    """绘制检测结果统计图表"""
    if not HAS_MATPLOTLIB:
        print("\n（matplotlib 未安装，跳过图表生成）")
        return

    plt.rcParams["font.sans-serif"] = ["DejaVu Sans", "SimHei", "Microsoft YaHei", "Arial"]
    plt.rcParams["axes.unicode_minus"] = False

    fig, axes = plt.subplots(2, 2, figsize=(14, 10))

    # 图1：风险等级分布柱状图
    ax1 = axes[0][0]
    levels = ["Low Risk", "Medium Risk", "High Risk"]
    counts = [stats["low"], stats["medium"], stats["high"]]
    colors = ["#4CAF50", "#FF9800", "#F44336"]
    bars = ax1.bar(levels, counts, color=colors, edgecolor="black", width=0.5)
    ax1.set_title("Risk Level Distribution", fontsize=14, fontweight="bold", pad=10)
    ax1.set_ylabel("Count")
    max_count = max(counts) if counts else 1
    ax1.set_ylim(0, max_count * 1.15)
    for bar, c in zip(bars, counts):
        ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + max_count * 0.02,
                 str(c), ha="center", fontsize=12, fontweight="bold")

    # 图2：正常 vs 攻击饼图
    ax2 = axes[0][1]
    labels = ["Normal", "Attack"]
    values = [stats["normal"], stats["attack"]]
    pie_colors = ["#4CAF50", "#F44336"]
    wedges, texts, autotexts = ax2.pie(
        values, labels=labels, colors=pie_colors, autopct="%1.1f%%",
        startangle=90, textprops={"fontsize": 12},
        pctdistance=0.6, labeldistance=1.1,
    )
    for at in autotexts:
        at.set_fontweight("bold")
    ax2.set_title("Normal vs Attack", fontsize=14, fontweight="bold", pad=10)

    # 图3：各规则命中次数水平柱状图
    ax3 = axes[1][0]
    rule_names = [r["name"] for r in DETECTION_RULES]
    rule_hits = [stats["rule_hit_count"].get(r["name"], 0) for r in DETECTION_RULES]
    truncated_names = [(n[:18] + "..") if len(n) > 20 else n for n in rule_names]
    ax3.barh(truncated_names, rule_hits, color="#2196F3", edgecolor="black", height=0.5)
    ax3.set_title("Rule Hit Count", fontsize=14, fontweight="bold", pad=10)
    ax3.set_xlabel("Hits")
    max_hits = max(rule_hits) if rule_hits and max(rule_hits) > 0 else 1
    ax3.set_xlim(0, max_hits * 1.2)
    for i, h in enumerate(rule_hits):
        ax3.text(h + max_hits * 0.02, i, str(h), va="center", fontsize=11)

    # 图4：风险得分分布直方图
    ax4 = axes[1][1]
    scores = [r["score"] for r in all_results]
    score_max = max(scores) if scores else 0
    ax4.hist(scores, bins=range(0, score_max + 2, 1), color="#673AB7",
             edgecolor="black", alpha=0.8, rwidth=0.85)
    ax4.set_title("Risk Score Distribution", fontsize=14, fontweight="bold", pad=10)
    ax4.set_xlabel("Score")
    ax4.set_ylabel("Count")
    ax4.set_xticks(range(0, score_max + 1))

    plt.subplots_adjust(hspace=0.35, wspace=0.3)
    plt.savefig("detection_report_charts.png", dpi=150, bbox_inches="tight")
    plt.close()
    print("\n[图表已保存到 detection_report_charts.png]")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Translation Prompt Injection Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python prompt_injection_detector.py
  python prompt_injection_detector.py --data my_data.jsonl --output ./results
  python prompt_injection_detector.py --method hybrid --eval
  python prompt_injection_detector.py --threshold 5
        """,
    )
    parser.add_argument(
        "--data", default="translation_pia_dataset_shuffled.jsonl",
        help="Path to JSONL dataset file",
    )
    parser.add_argument(
        "--output", "-o", default=".",
        help="Output directory for reports",
    )
    parser.add_argument(
        "--threshold", type=int, default=3,
        help="Score threshold for attack classification (default: 3)",
    )
    parser.add_argument(
        "--method", choices=["regex", "llm", "hybrid"], default="regex",
        help="Detection method (default: regex)",
    )
    parser.add_argument(
        "--eval", action="store_true",
        help="Run evaluation against ground truth labels",
    )
    parser.add_argument(
        "--provider", default=None,
        choices=list(PROVIDER_ENDPOINTS.keys()),
        help="LLM provider (default: anthropic)",
    )
    parser.add_argument(
        "--model", default=None,
        help="LLM model name (auto-selected per provider if not set)",
    )
    parser.add_argument(
        "--no-charts", action="store_true",
        help="Skip chart generation",
    )
    args = parser.parse_args()

    data_file = args.data
    if not os.path.exists(data_file):
        print(f"Error: data file not found: {data_file}", file=sys.stderr)
        sys.exit(1)

    print(f"Loading data file: {data_file}\n")

    texts: list[str] = []
    text_ids: list[str] = []
    records: list[dict[str, Any]] = []

    with open(data_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                texts.append(record["text"])
                text_ids.append(record["id"])
                records.append(record)
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Warning: skipping malformed line: {e}", file=sys.stderr)

    total_count = len(texts)
    print(f"Loaded {total_count} texts.\n")

    print("Preprocessing texts...")
    cleaned_texts = batch_preprocess(texts)
    print("Preprocessing complete.\n")

    # Build config with CLI overrides for LLM/hybrid modes
    config = load_config()
    if args.provider:
        config.llm_provider = args.provider
    if args.model:
        config.llm_model = args.model

    # Select detection method
    if args.method == "regex":
        threshold = args.threshold
        detector_fn = lambda t: detect_injection(t, threshold=threshold)
        print(f"Running regex-based detection (threshold={threshold})...")
    elif args.method == "llm":
        from llm_detector import create_llm_detector
        llm = create_llm_detector(config)
        detector_fn = llm.detect
        provider = config.llm_provider
        print(f"Running LLM-based detection ({provider}/{config.llm_model})...")
    elif args.method == "hybrid":
        from llm_detector import create_hybrid_detector
        detector_fn = create_hybrid_detector(config)
        provider = config.llm_provider
        print(f"Running hybrid detection ({provider}/{config.llm_model})...")
    else:
        raise ValueError(f"Unknown detection method: {args.method}")

    all_results = [detector_fn(t) for t in cleaned_texts]
    print("Detection complete.")

    # Write detailed report
    os.makedirs(args.output, exist_ok=True)
    report_file = os.path.join(args.output, "detection_report.txt")
    with open(report_file, "w", encoding="utf-8") as f:
        print_separator("=", 80, file=f)
        print("                    <<< 逐条检测报告 >>>", file=f)
        print_separator("=", 80, file=f)
        for j in range(total_count):
            print_single_result(text_ids[j], texts[j], all_results[j], file=f)
        stats = print_summary_report(all_results, total_count, file=f)

    print(f"Report saved to: {report_file}")

    # Print summary to terminal
    print_summary_report(all_results, total_count)

    if not args.no_charts:
        draw_charts(stats, all_results)

    # Evaluation mode
    if args.eval:
        print("\n" + "=" * 80)
        print("Running evaluation against ground truth labels...")
        print("=" * 80)
        from evaluator import run_evaluation, save_evaluation_reports, plot_evaluation_charts

        eval_result = run_evaluation(detector_fn, data_file)
        save_evaluation_reports(eval_result, args.output)
        if not args.no_charts:
            plot_evaluation_charts(eval_result, args.output)

        print(f"\nAccuracy: {eval_result.accuracy:.4f}")
        print(f"Precision: {eval_result.precision:.4f}")
        print(f"Recall: {eval_result.recall:.4f}")
        print(f"F1 Score: {eval_result.f1:.4f}")

if __name__ == "__main__":
    main()
