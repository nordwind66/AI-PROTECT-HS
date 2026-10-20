"""Shared vocabulary of the rule model (single definition used by importers, validators, publisher)."""
from __future__ import annotations

CATEGORIES = [
    "prompt_injection", "jailbreak", "role_spoofing", "instruction_override",
    "instruction_hijacking", "system_prompt_extraction", "safety_bypass",
    "obfuscated_injection", "data_exfiltration_instruction",
]
CATEGORY_CODE = {
    "prompt_injection": "PI", "jailbreak": "JB", "role_spoofing": "RS", "instruction_override": "IO",
    "instruction_hijacking": "IH", "system_prompt_extraction": "SP", "safety_bypass": "SB",
    "obfuscated_injection": "OB", "data_exfiltration_instruction": "DX",
}
SEVERITIES = ["info", "low", "medium", "high", "critical"]
LANGS = ["zh", "en", "mixed", "any"]
ACTIONS = ["allow", "alert", "review", "block"]
SCOPES = ["general", "translation_only", "context_required"]
PROFILES = {
    "fold_v1": {"views": ["fold_v1", "raw"]},     # normalised view first, raw text as fallback (ATR semantics)
    "deobf_v1": {"views": ["deobf_v1", "fold_v1", "raw"]},  # fold_v1 + anti-obfuscation view (CJK spacing, spelled-out words, leetspeak)
    "trans_v1": {"views": ["trans_v1"]},          # exact preprocessing of the translation detector
    "raw_v1": {"views": ["raw"]},
}

# Sources a caller can declare for a text, and the rule fields each source supplies.
# This mirrors ATR's field resolution (src/engine.ts resolveField): on a tool_response event the
# tool/MCP/RAG output IS the text the model ingests, so llm_io rules that target user_input or
# agent_output resolve to the same content there; `content` is always available.
SOURCES = ["user_input", "tool_output", "rag_document", "agent_message"]
SOURCE_FIELD_MAP = {
    "user_input": ["user_input", "content"],
    "tool_output": ["tool_response", "user_input", "agent_output", "content"],
    "rag_document": ["tool_response", "user_input", "agent_output", "content"],
    "agent_message": ["agent_output", "agent_message", "content"],
}
# Fields a rule condition may be bound to; anything else (trace.*, behavioral.*) is out of scope.
KNOWN_FIELDS = {"user_input", "content", "tool_response", "agent_output", "agent_message", "tool_args",
                "tool_name", "tool_description", "tool_input"}
# ATR agent_source.type -> the source the reference test harness routes test inputs to
AGENT_TYPE_TO_SOURCE = {
    "llm_io": "user_input", "tool_call": "user_input", "mcp_exchange": "tool_output",
    "agent_behavior": "user_input", "multi_agent_comm": "agent_message", "context_window": "user_input",
    "memory_access": "user_input", "skill_lifecycle": "user_input", "skill_permission": "user_input",
    "skill_chain": "user_input",
}
