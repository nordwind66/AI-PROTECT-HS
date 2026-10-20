/**
 * ATR-to-Generic-Regex Converter
 *
 * Exports ATR rules as a flat list of regex patterns with metadata.
 * Designed for consumption by any security tool that supports regex matching.
 * Format: JSON array of { id, title, severity, category, patterns[] }
 *
 * Used by: Cisco AI Defense, Microsoft Agent Governance Toolkit, custom integrations.
 *
 * @module agent-threat-rules/converters/generic-regex
 */

import type { ATRRule, ATRSeverity, ATRReferences } from '../types.js';

export interface GenericRegexRule {
  readonly id: string;
  readonly title: string;
  readonly severity: ATRSeverity;
  readonly category: string;
  readonly subcategory: string;
  readonly scan_target: string;
  readonly patterns: readonly GenericRegexPattern[];
  readonly references: ATRReferences | undefined;
}

export interface GenericRegexPattern {
  readonly field: string;
  readonly regex: string;
  readonly flags: string;
  readonly description: string;
}

/**
 * Convert a single ATR rule to generic regex format.
 */
export function ruleToGenericRegex(rule: ATRRule): GenericRegexRule {
  const patterns: GenericRegexPattern[] = [];

  // ATRConditions can be an array or a named record
  const conditions = Array.isArray(rule.detection.conditions)
    ? rule.detection.conditions
    : Object.values(rule.detection.conditions);

  for (const condition of conditions) {
    if ('operator' in condition && condition.operator === 'regex' && 'value' in condition && condition.value) {
      // Extract flags from the regex (e.g. (?i) → 'i')
      let regex = condition.value;
      let flags = '';
      const flagMatch = regex.match(/^\(\?([gimsuy]+)\)/);
      if (flagMatch) {
        flags = flagMatch[1]!;
        regex = regex.slice(flagMatch[0].length);
      }

      patterns.push({
        field: 'field' in condition ? condition.field : 'content',
        regex,
        flags,
        description: ('description' in condition ? condition.description : '') ?? '',
      });
    }
  }

  return {
    id: rule.id,
    title: rule.title,
    severity: rule.severity,
    category: rule.tags.category,
    subcategory: rule.tags.subcategory ?? '',
    scan_target: rule.tags.scan_target ?? 'mcp',
    patterns,
    references: rule.references ?? {},
  };
}

/**
 * Convert all ATR rules to a single generic regex export.
 */
export function rulesToGenericRegex(rules: readonly ATRRule[]): readonly GenericRegexRule[] {
  return rules
    .filter((r) => r.status !== 'deprecated')
    .map(ruleToGenericRegex)
    .filter((r) => r.patterns.length > 0);
}
