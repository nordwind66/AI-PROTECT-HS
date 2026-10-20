/**
 * ATR SIEM Query Converter
 *
 * Converts ATR YAML rules into SIEM-specific query formats
 * (Splunk SPL and Elasticsearch Query DSL).
 *
 * @module agent-threat-rules/converters
 */

import type { ATRRule } from '../types.js';
import { loadRulesFromDirectory } from '../loader.js';
import { ruleToSPL } from './splunk.js';
import { ruleToElastic } from './elastic.js';

export type SIEMFormat = 'splunk' | 'elastic';
export type OutputFormat = SIEMFormat | 'sarif' | 'generic-regex';

export interface ConvertedQuery {
  readonly ruleId: string;
  readonly title: string;
  readonly severity: string;
  readonly format: SIEMFormat;
  readonly query: string; // SPL string or JSON string
}

/**
 * Convert a single ATR rule to a SIEM query.
 */
export function convertRule(rule: ATRRule, format: SIEMFormat): ConvertedQuery {
  const query = format === 'splunk'
    ? ruleToSPL(rule)
    : JSON.stringify(ruleToElastic(rule), null, 2);

  return {
    ruleId: rule.id,
    title: rule.title,
    severity: rule.severity,
    format,
    query,
  };
}

/**
 * Convert all ATR rules in a directory to SIEM queries.
 */
export function convertAllRules(rulesDir: string, format: SIEMFormat): readonly ConvertedQuery[] {
  const rules = loadRulesFromDirectory(rulesDir);
  return rules.map(rule => convertRule(rule, format));
}

export { ruleToSPL } from './splunk.js';
export { ruleToElastic } from './elastic.js';
export { scanResultToSARIF } from './sarif.js';
export { ruleToGenericRegex, rulesToGenericRegex } from './generic-regex.js';
export type { GenericRegexRule, GenericRegexPattern } from './generic-regex.js';
export { atrToSage, atrToSageBatch, sageRulesToYaml, SageIdAllocator } from './sage.js';
export type {
	SageRule,
	SageSeverity,
	SageAction,
	SageMatchOn,
	ConvertResult as SageConvertResult,
	ConversionWarning as SageConversionWarning,
} from './sage.js';
export { sageToAtr, sageToAtrBatch } from './sage-reverse.js';
export type { ReverseConvertResult, ReverseWarning } from './sage-reverse.js';
