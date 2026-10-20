# ATR L1 Baseline Conformance Fixtures

> **STATUS: PROPOSED v1.0 — populating begun 2026-05-25.** This is the
> ground-truth input/output corpus that any conformant ATR engine MUST
> reproduce. See `../README.md` for the level definitions and
> `../../README.md` for spec index.

---

## Directory layout

```
fixtures/
└── <fixture_id>/
    ├── input.json     ← the AgentEvent fed into the engine
    └── expected.json  ← the ATREvent shape the engine MUST produce
```

## Fixture ID convention

`<rule-id>-<kind>-<seq>` where:

- `<rule-id>` is the canonical or sovereign rule identifier (e.g.,
  `ATR-2026-00001`, `ATR-COR-2026-00001`, `ATR-TW-2026-00001`).
- `<kind>` is one of:
  - `tp` — true positive (rule should fire)
  - `tn` — true negative (rule must NOT fire)
  - `evasion` — known evasion attempt (rule should still fire)
  - `multi` — input that exercises multiple rules
- `<seq>` is a zero-padded sequence number within the rule + kind.

Examples:
- `ATR-2026-00001-tp-001` — rule 00001, first true-positive fixture
- `ATR-2026-00001-tn-003` — rule 00001, third true-negative fixture
- `ATR-2026-00001-evasion-001` — rule 00001, first evasion fixture

## input.json schema

```json
{
  "fixture_id": "string (matches directory name)",
  "fixture_kind": "true_positive | true_negative | evasion | multi",
  "description": "string (human-readable, sources cited)",
  "target_rule": "string (the primary rule this fixture exercises)",
  "input_event": {
    "type": "AgentEventType (per atr-event-v1.0.md)",
    "timestamp": "RFC 3339",
    "content": "string (optional)",
    "fields": { "...": "..." },
    "metadata": { "...": "..." },
    "sessionId": "string",
    "scanContext": "runtime | skill | agent_message | ..."
  }
}
```

## expected.json schema

```json
{
  "fixture_id": "string (matches directory name)",
  "expected_match": "bool (true if any rule should fire)",
  "expected_rules_fired": ["array of rule_id strings"],
  "expected_event_shape": {
    "atr.rule_id": "must-match",
    "atr.severity": "must-match",
    "atr.category": "must-match",
    "...": "engine-supplied fields use <engine-supplied> sentinel"
  },
  "match_tolerance": {
    "min_confidence": "float 0..1",
    "max_confidence": "float 0..1",
    "allow_additional_rule_matches": "bool",
    "additional_match_allowlist": ["array of rule_ids permitted to also fire"]
  },
  "notes": ["array of human-readable conformance reasoning"]
}
```

## Conformance verdict

For each fixture, the verdict is one of:

- **PASS** — engine fired exactly the rules in `expected_rules_fired` (or
  fired those plus rules in `additional_match_allowlist`), with event
  fields matching `expected_event_shape` (modulo `<engine-supplied>`
  sentinels), and `confidence` within `match_tolerance`.
- **FAIL** — any required rule did not fire, OR any forbidden rule fired,
  OR event shape mismatch on a MUST-match field.
- **PARTIAL** — required rules fired but field shape was off (e.g., wrong
  severity). Treated as FAIL for L1 conformance claim, but reported
  separately for diagnostic.

L1-baseline pass threshold is in `../manifest.json` (precision 1.00,
recall 0.95).

## Current fixture count

| Status | Count | Note |
|---|---|---|
| Populated | 1 | ATR-2026-00001-tp-001 |
| Targeted for v1.0 ratification | ~100 | one TP + one TN per stable canonical rule |
| Targeted for L2 (profile) | TBD | covers `atr-baseline-runtime` and `atr-nist-rmf-measure` |
| Targeted for L3 (correlation) | TBD | exercises each correlation type at least once |

Contributors: open a PR adding a fixture directory. CI will validate
schema. Maintainer review confirms the test case is canonical.

## Provenance

Fixtures are sourced from:

1. Rule `test_cases` blocks (already-validated true positives and
   negatives that ship with each rule).
2. Public CVE reproductions where ATR rules exist (e.g., CVE-2024-5184
   for ATR-2026-00001).
3. Published academic adversarial datasets (PINT MCP, Garak, METR,
   SpAIware) where licensing permits.
4. Community-contributed adversarial inputs (under DCO sign-off per
   `legal/CLA.md`).
