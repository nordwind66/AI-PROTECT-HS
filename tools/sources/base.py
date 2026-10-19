"""Importer plugin interface.

A *source importer* turns one locked upstream repository into a list of `SrcRule` objects -- the
normalised intermediate representation (IR). The importer never touches the database and never
executes upstream code (YAML via miniyaml, Python via `ast`). Everything downstream (language
scoping, regex conversion, de-duplication, ID allocation, SQLite writes) is source independent, so
a fourth rule source only needs a new module in tools/sources/ plus an entry in
third_party/sources.def.json -- the engine does not change.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from apg_rules.model import (AGENT_TYPE_TO_SOURCE, CATEGORIES, CATEGORY_CODE, KNOWN_FIELDS, SEVERITIES,  # noqa: F401
                             SOURCE_FIELD_MAP, SOURCES)


@dataclass
class SrcPattern:
    ordinal: int
    key: str                          # leaf alias inside the rule (also used by boolean expressions)
    regex: str
    flags: str = ""
    dialect: str = "es"               # es | py | pcre
    field_name: str = "content"
    operator: str = "regex"
    description: str = ""
    locator: str = ""
    line_no: Optional[int] = None
    force_flags: str = ""             # flags the SOURCE ENGINE applies regardless of the pattern
    pre_fate: Optional[str] = None    # importer already decided (excluded_scope / unsupported / context_logic)
    pre_reason: str = ""


@dataclass
class SrcTest:
    kind: str                         # positive | negative | known_gap
    text: str
    expect_hit: bool
    description: str = ""
    scan_source: str = "user_input"
    locator: str = ""
    origin: str = "upstream"          # upstream | manual (written by this project) | generated
    fields: Dict[str, str] = field(default_factory=dict)   # extra named fields (tool_name, tool_args ...)


@dataclass
class UnifiedHint:
    """The importer's proposal for the unified rule derived from this source rule."""
    name: str
    category: str
    severity: str
    weight: float
    confidence: float
    default_action: str = "alert"
    status: str = "enabled"                   # enabled | disabled | deprecated
    scope: str = "general"                    # general | translation_only | context_required
    context_requires: Optional[Dict[str, Any]] = None
    score_group: Optional[str] = None
    description: str = ""
    tags: List[str] = field(default_factory=list)
    norm_profile: str = "deobf_v1"
    category_reason: str = ""


@dataclass
class SrcRule:
    source_key: str
    name: str
    source_path: str
    raw: Dict[str, Any]                       # trimmed original definition (JSON-able)
    combinator: str                           # any | all | <boolean expression>
    patterns: List[SrcPattern]
    tests: List[SrcTest] = field(default_factory=list)
    decision: str = "included"                # included | excluded_scope | unsupported | context_logic
    decision_reason: str = ""
    unified: Optional[UnifiedHint] = None
    group_key: Optional[str] = None
    locator: str = ""
    upstream_status: str = ""
    upstream_severity: str = ""
    upstream_maturity: str = ""
    upstream_confidence: Optional[float] = None
    lang_declared: str = ""
    file_blob_sha: str = ""
    # JSON condition tree over leaf keys: {"op":"any|all|not","args":[...]} / {"op":"leaf","id":"c1"}
    cond_tree: Optional[Dict[str, Any]] = None


@dataclass
class ExtractResult:
    rules: List[SrcRule]
    warnings: List[str] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)


class SourceImporter:
    """Base class; subclasses are discovered by tools/sources/__init__.py."""
    source_id: str = ""
    importer_id: str = ""
    version: str = "1"

    def extract(self, root: Path, lock_entry: Dict[str, Any], log: Callable[[str], None]) -> ExtractResult:
        raise NotImplementedError

    def blob_sha(self, lock_entry: Dict[str, Any], rel_path: str) -> str:
        for f in lock_entry.get("files", []):
            if f["path"] == rel_path:
                return f["git_blob"]
        return ""
