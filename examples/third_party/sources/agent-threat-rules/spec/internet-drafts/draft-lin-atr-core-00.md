---
title: "Agent Threat Rules (ATR): An Open Detection Standard for AI Agent Security Threats"
abbrev: "ATR Core"
docname: draft-lin-atr-core-00
category: std
ipr: trust200902
area: Security
workgroup: SECEVENT
keyword:
  - AI agent
  - prompt injection
  - tool poisoning
  - MCP
  - detection rule
  - YAML
stand_alone: yes
pi:
  toc: yes
  tocompact: yes
  tocdepth: 3
author:
  - ins: K-H. Lin
    name: Kuan-Hsin Lin
    organization: ATR Project / Panguard AI, Inc.
    email: adam@agentthreatrule.org
    uri: https://agentthreatrule.org
normative:
  RFC2119:
  RFC8174:
  RFC5234:
informative:
  SIGMA:
    title: "Sigma Rule Specification"
    target: https://github.com/SigmaHQ/sigma-specification
  STIX21:
    title: "STIX Version 2.1 OASIS Standard"
    target: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
  NIST-AI-RMF:
    title: "Artificial Intelligence Risk Management Framework (AI 100-1)"
    target: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.100-1.pdf
  NIST-GAI-PROFILE:
    title: "NIST AI 600-1 Generative AI Profile"
    target: https://nvlpubs.nist.gov/nistpubs/ai/NIST.AI.600-1.pdf
  OWASP-AGENTIC:
    title: "OWASP Agentic Security Initiative Top 10 (2026)"
    target: https://genai.owasp.org/llm-top-10/agentic-top-10/
  MITRE-ATLAS:
    title: "MITRE Adversarial Threat Landscape for AI Systems"
    target: https://atlas.mitre.org/
---

--- abstract

This document specifies the Agent Threat Rules (ATR) Core Specification, an
open, vendor-neutral detection rule standard for AI agent security threats.
ATR is analogous in role to Sigma {{SIGMA}} for SIEM but applies to AI agent
artifacts (skill descriptions, MCP tool definitions, agent configurations)
and AI agent runtime events (LLM input/output, tool invocations, context
windows). The specification defines the rule wire format in YAML 1.2, the
canonical rule identifier scheme, evaluation semantics with explicit
combinator and operator vocabularies, match output structure, ten canonical
threat categories, and three conformance levels. The intent is to enable
interoperable detection across independent implementations and to provide a
machine-readable layer that operationalizes policy frameworks such as
{{NIST-AI-RMF}}, {{NIST-GAI-PROFILE}}, {{OWASP-AGENTIC}}, and {{MITRE-ATLAS}}.

--- middle

# Introduction

AI agents now browse the web, run code, and invoke external tools. The
attack surface they expose is observable: prompt injections, tool
description poisoning, context window exfiltration, credential leakage
through agent-controlled HTTP traffic, and configuration files that take
effect before any human trust dialog. Several policy frameworks describe
these risks, but none of them are directly executable by a scanner. ATR
fills that gap with a vendor-neutral rule format, a stable identifier
scheme, and a conformance test suite that lets independent implementations
agree on whether a given input matches a given rule.

ATR rules are YAML documents. Each rule has a globally unique identifier
of the form `ATR-YYYY-NNNNN` assigned by the project's Numbering Authority.
A conforming engine loads the rule corpus and emits Match outputs for
inputs that satisfy the rule's detection condition. The Specification is
intentionally narrow: it defines wire format, identifiers, evaluation
semantics, match output, and three conformance levels. Higher-level
governance (rule contribution, deprecation, trademark policy) lives in
companion documents in the project repository.

## Relationship to Existing Standards

ATR is the executable detection layer for AI agent threats. It cites
adjacent standards rather than replacing them:

- {{NIST-AI-RMF}} and {{NIST-GAI-PROFILE}} define risk management functions
  (Govern, Map, Measure, Manage). ATR provides detection rules that
  populate the Measure function at scan time, with a Cross-walk in
  {{cross-walk}}.
- {{OWASP-AGENTIC}} and {{MITRE-ATLAS}} categorize adversarial behaviors.
  ATR rule metadata maps each rule to specific categories and techniques
  in these frameworks.
- {{STIX21}} provides a CTI interchange envelope. ATR Match output can be
  emitted in STIX 2.1 via the `x-atr-rule` extension defined in the
  project repository.

# Conventions and Terminology

{::boilerplate bcp14-tagged}

| Term | Definition |
|------|-----------|
| Rule | A YAML document conforming to {{rule-document-structure}} that describes one detection pattern. |
| Rule ID | A globally unique identifier in the form `ATR-YYYY-NNNNN`, see {{rule-identifier}}. |
| Engine | Software that loads Rules and evaluates Inputs against them. |
| Input | A structured artifact or AgentEvent submitted for evaluation. |
| Match | An Engine's output indicating that a Rule's detection condition evaluated to true for a given Input. |
| Numbering Authority | The body authorized to assign permanent Rule IDs (see project Governance document). |
| Conformance Level | One of L1, L2, L3, see {{conformance-levels}}. |
| Corpus | The set of Rules officially published under a given ATR version. |

# Rule Identifier  {#rule-identifier}

## Format

A Rule ID conforms to the following ABNF {{RFC5234}}:

~~~ abnf
rule-id   = "ATR" "-" year "-" sequence
year      = 4DIGIT
sequence  = 5DIGIT
DIGIT     = %x30-39
~~~

## Assignment Rules

1. Rule IDs MUST be assigned by the Numbering Authority and MUST NOT be
   self-assigned by contributors.
2. Once assigned, a Rule ID MUST be considered permanent and MUST NOT be
   reassigned, even if the originally-assigned Rule is deprecated.
3. A Rule ID MUST NOT encode classification information (category,
   severity, scan target). Classification is carried in metadata fields
   per {{rule-document-structure}}.
4. A Rule ID MUST be globally unique within the official Corpus.
5. Contributors SHOULD use a placeholder identifier of the form
   `ATR-YYYY-DRAFT-<hex>` in pull requests prior to merge.

# Rule Document Structure  {#rule-document-structure}

A conforming Rule is a UTF-8 encoded YAML 1.2 document whose top-level
value is a mapping containing at minimum the fields defined in this
section. Engines MUST preserve unknown top-level fields when round-tripping
Rules but MUST NOT allow such fields to alter evaluation outcomes.

The full field schema, including required and optional fields with type
constraints, is given in the project's `spec/atr-schema.yaml` and tracked
in this document by reference. Required top-level keys are:

`id`, `title`, `status`, `description`, `author`, `date`, `severity`,
`tags`, `agent_source`, `detection`, `response`, `test_cases`.

# Detection Semantics

## Match Definition

Given a Rule R and an Input I, an Engine MUST emit a Match if, and only
if, all conditions in `R.detection.condition` evaluate to true against I
per the combinator semantics in {{condition-combinators}}.

## Condition Combinators  {#condition-combinators}

`R.detection.condition` is a logical expression over named selectors
declared in `R.detection.selectors`. Engines MUST implement:

| Combinator | Semantics |
|------------|-----------|
| `S` | true iff selector S matches |
| `S1 and S2` | true iff both S1 and S2 match |
| `S1 or S2` | true iff S1 or S2 matches |
| `not S` | true iff S does not match |
| `all of S*` | true iff every selector matched by the wildcard matches |
| `1 of S*` | true iff at least one selector matched by the wildcard matches |

## Selector Operators

Engines MUST implement the operators below with the given semantics:
`contains`, `contains_i`, `regex` (ECMAScript-compatible), `equals`,
`startswith`, `endswith`, `length_gt`, `length_lt`, `in`.

Engines SHOULD reject Rules using operators outside this set with a
clear error message. Engines MAY support additional operators but MUST
treat such Rules as non-portable.

## Determinism

For a given Engine version, a given Rule, and a given Input, the Match
outcome MUST be deterministic. Engines MUST NOT introduce non-determinism
(e.g., sampling, time-of-day branching) into Rule evaluation.

# Match Output

An Engine MUST emit Match output that includes, at minimum, a `rule_id`,
the `rule_version` it was loaded from, a stable `input_identifier`, the
`matched_at` timestamp (ISO 8601), the rule `severity`, the rule
`category`, and the list of `matched_selectors`. Engines MAY emit
additional fields and MAY use JSON, SARIF, STIX 2.1, or other
serializations.

# Canonical Categories

The following ten categories are normative for the current Specification.
New categories are introduced only by Specification amendment.

1. `prompt-injection`
2. `agent-manipulation`
3. `skill-compromise`
4. `context-exfiltration`
5. `tool-poisoning`
6. `privilege-escalation`
7. `model-abuse`
8. `excessive-autonomy`
9. `model-security`
10. `data-poisoning`

# Cross-walk  {#cross-walk}

A Rule MAY include a `compliance` object mapping its detection to external
frameworks. Identifiers MUST come from the authoritative source for each
framework. Where ambiguity exists, Rule authors SHOULD include a
`references` entry pointing to the source document. Cross-walks defined
for the current Specification include OWASP Agentic Top 10, OWASP LLM
Top 10, MITRE ATLAS, NIST AI RMF, ISO/IEC 42001, EU AI Act, and
SAFE-MCP.

# Conformance Levels  {#conformance-levels}

| Level | Requirement |
|-------|-------------|
| L1 | Engine loads the published Corpus without parse errors and emits Match output for at least one Rule. |
| L2 | Engine passes 100 percent of the Conformance Test Suite for the declared Spec version. |
| L3 | Engine passes L2, emits Match output in at least two interchange formats (JSON plus one of SARIF, STIX 2.1, MISP, OpenCTI), and publishes its results against the public benign Corpus with documented false-positive rate. |

An implementation MAY claim "ATR-Compatible" only with a declared
Conformance Level and a reproducible test report.

# Security Considerations

Rules are content that an Engine evaluates against potentially untrusted
Inputs. An Engine MUST NOT permit a Rule's free-form metadata fields
(`description`, `references`) to alter evaluation behavior. Only fields
listed in {{rule-document-structure}}, {{detection-semantics}}, and
match-output sections affect evaluation.

A malformed `regex` selector may cause catastrophic backtracking. Engines
MUST apply a per-rule execution timeout (RECOMMENDED: 100 ms per Input
per Rule) and MUST report a timeout as a non-match rather than an error.

If a Rule's matched substring contains PII or sensitive credentials,
Engines SHOULD provide a redaction option that hashes or truncates the
matched substring before emitting Match output.

# IANA Considerations

This document requests registration of the following media types:

- `application/vnd.atr.rule+yaml` — a single ATR Rule
- `application/vnd.atr.corpus+yaml` — a corpus manifest listing multiple Rules
- `application/vnd.atr.match+json` — Match output

Registration templates are included as Appendix B of the project's
SPEC.md and will be filed with IANA on advancement of this document.

--- back

# Acknowledgments

The author acknowledges contributions from external maintainers at
Cisco AI Defense, MISP / CIRCL, Microsoft Agent Governance Toolkit,
Gen Digital Sage, and the OWASP Gen AI Security Project, as well as
researchers at NVIDIA garak and the HackAPrompt 2023 competition whose
attack payloads seeded the rule corpus.

# Editorial Notes (to be removed before publication)

This is the `-00` revision. Subsequent revisions will incorporate IETF
SECEVENT working-group feedback. The corresponding full project
specification is maintained at
https://github.com/Agent-Threat-Rule/agent-threat-rules/blob/main/SPEC.md
and tracks this document by reference until working-group adoption.
