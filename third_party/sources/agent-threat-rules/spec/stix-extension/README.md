# Agent Threat Rules (ATR) — STIX 2.1 Extension

This directory defines a STIX 2.1 extension that introduces the
`x-atr-rule` custom Domain Object so ATR rules can be represented
natively in STIX/TAXII threat-intelligence pipelines.

**Current version: 1.1.0** (2026-05-28). See [Changelog](#changelog) below.

## Why a STIX extension

ATR rules are an open detection vocabulary for AI agent threats —
prompt injection, tool poisoning, MCP server attacks, skill compromise,
plus the v1.1 trace-method rules for silent failures and scope drift.
They were adopted as a MISP taxonomy in [MISP/misp-taxonomies#323][misp-tax]
on 2026-05-10 and a MISP galaxy in [MISP/misp-galaxy#1207][misp-gal].

Several CTI consumers use STIX/TAXII rather than MISP. Mapping ATR to a
generic STIX `indicator` or `attack-pattern` object is lossy: the
ten-category attack class, regex detection patterns, severity, the
five-plane detection method (v1.1), and the compliance-framework references
(EU AI Act, NIST AI RMF, NIST CSF 2.0, ISO 42001, ETSI TS 104 223, OSCAL)
all get flattened. This extension preserves them as first-class fields on
a new `x-atr-rule` SDO.

## Files

- [`extension-definition.json`](./extension-definition.json) — the
  STIX 2.1 Extension Definition object. Stable id
  `extension-definition--93370194-c964-570f-9802-9d1154e5525d`. Consumers
  reference this id in the `extensions` map of every `x-atr-rule`
  instance. v1.1.0 as of 2026-05-28.
- [`x-atr-rule-schema.json`](./x-atr-rule-schema.json) — JSON Schema
  (Draft 7) for the new SDO. Defines required fields, enum values for
  `atr_category` / `atr_method` / `atr_runtime_profile` / `severity` /
  `agent_source_type` / `response_actions`, and structural constraints
  on `detection_patterns`, `signature_indicators`, `semantic_judge`,
  `trace_detection`, and `compliance_refs`.
- [`examples/atr-rule-prompt-injection-example.json`](./examples/atr-rule-prompt-injection-example.json)
  — pattern-method instance for `ATR-2026-00001`.
- [`examples/atr-rule-trace-method-example.json`](./examples/atr-rule-trace-method-example.json)
  — v1.1 trace-method instance for `ATR-2026-00548`. Shows the
  `trace_detection` payload with the `invariant` primitive.

## Identifier convention

`x-atr-rule.id` is recommended to be a deterministic UUIDv5 derived
from the canonical ATR rule id (e.g. `ATR-2026-00548`) under the
namespace UUID `6f7a8b9c-1d2e-4f5a-9b8c-7e6d5f4a3b2c`. The same rule id
therefore always produces the same STIX id across consumers, which lets
multiple feeds align without conflict resolution.

## Method-specific payload mapping (v1.1)

The `atr_method` field selects which optional payload field is populated:

| `atr_method` | Required companion field | Maps to ATR YAML |
|--------------|--------------------------|------------------|
| `pattern` | `detection_patterns` | `detection.conditions` |
| `signature` | `signature_indicators` | `detection.signature.indicators` |
| `semantic` | `semantic_judge` | `detection.semantic` |
| `behavioral` | (placeholder; spec §7) | — |
| `trace` | `trace_detection` | `detection.trace` |

For multi-method rules (e.g., rule 00552 uses both invariant AND forbid
inside one trace block), all primitives ship under `trace_detection.primitives`.

## Extension type

`extension_types: ["new-sdo"]` per STIX 2.1 §7.3, which is the correct
designation for introducing a brand-new top-level Domain Object type.
The schema field on the Extension Definition points at the JSON Schema
in this directory via raw GitHub URL so the schema is dereferenceable
for validating consumers.

## MISP export hint

Consumers that bridge STIX → MISP can map `x-atr-rule` to MISP objects:

| `x-atr-rule` field | MISP object / attribute |
|--------------------|-------------------------|
| `atr_id` | `external-references[type=external_analysis]` or first `atr` attribute |
| `atr_category` | MISP taxonomy `atr:category="<value>"` (via misp-taxonomies#323) |
| `severity` | MISP `threat-level` |
| `detection_patterns[].pattern` | `pattern-in-file` attribute (one per regex) |
| `signature_indicators[].value` | MISP `sha256` / `filename` / `url` attribute by `type` |
| `cve_refs` | MISP `vulnerability` attribute |
| `mitre_atlas_refs` | MISP galaxy `mitre-atlas-techniques` |
| `compliance_refs.*` | MISP free-form tag, namespace per framework |

A reference STIX→MISP transpiler is planned at `scripts/export-stix-to-misp.ts`.

## Validation

```bash
python3 -m pip install jsonschema
python3 -c "import json, jsonschema; \
  schema = json.load(open('spec/stix-extension/x-atr-rule-schema.json')); \
  example = json.load(open('spec/stix-extension/examples/atr-rule-prompt-injection-example.json')); \
  jsonschema.validate(example, schema); \
  trace_example = json.load(open('spec/stix-extension/examples/atr-rule-trace-method-example.json')); \
  jsonschema.validate(trace_example, schema); \
  print('OK')"
```

## Changelog

### v1.1.0 — 2026-05-28
- Added `atr_method` enum field (pattern / signature / semantic / behavioral / trace).
- Added `atr_runtime_profile` enum field (deterministic / assisted).
- Added 10th category `model-security` to `atr_category` enum.
- Added `agent_trace` to `agent_source_type` enum.
- Added method-specific payload objects: `signature_indicators`,
  `semantic_judge`, `trace_detection`.
- Added `probe_id_refs` for adversarial probe binding (PyRIT / garak / etc).
- Added compliance fields: `nist_csf`, `etsi_ts_104223`, `oscal_assessment_objective`.
- Added `owasp_ast_refs`, `safe_mcp_refs`.
- Extended `response_actions` enum with SPEC.md Appendix A canonical
  vocabulary (`block_request`, `log_alert`, `redact_match`, etc).
- Added `draft` to `maturity` enum to match on-disk rule status vocabulary.
- New example: `examples/atr-rule-trace-method-example.json`.

### v1.0.0 — 2026-05-11
- Initial release. Nine categories. Pattern-method only.

## Status

Draft v1.1.0. Not yet submitted to the OASIS CTI Technical Committee.
The extension is usable today by any consumer that processes STIX
extensions per the spec; OASIS submission becomes relevant if a
subset of fields ends up wanting promotion into core STIX.

## Related

- Canonical ATR repo: <https://github.com/Agent-Threat-Rule/agent-threat-rules>
- ATR YAML schema: [`../atr-schema.yaml`](../atr-schema.yaml)
- ATR Core Specification: [`../../SPEC.md`](../../SPEC.md)
- ATR Method Extensions: [`../atr-method-v1.1.md`](../atr-method-v1.1.md)
- npm: <https://www.npmjs.com/package/agent-threat-rules>
- DOI: 10.5281/zenodo.19178002

[misp-tax]: https://github.com/MISP/misp-taxonomies/pull/323
[misp-gal]: https://github.com/MISP/misp-galaxy/pull/1207
