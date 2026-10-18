/**
 * ATR Quality Standard — Rule Format Adapters
 *
 * Adapters convert vendor-specific rule formats into the canonical
 * RuleMetadata interface that the scoring and validation functions consume.
 *
 * @module agent-threat-rules/quality/adapters
 */

export { parseATRRule, atrRuleToMetadata } from "./atr.js";
