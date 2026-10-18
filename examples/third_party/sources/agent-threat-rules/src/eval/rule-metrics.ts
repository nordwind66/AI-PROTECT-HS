/**
 * Per-Rule Quality Metrics -- computes TP, FP, precision, recall,
 * and confidence stats for each individual rule based on eval results.
 *
 * All functions are pure (no side effects, no mutation).
 *
 * @module agent-threat-rules/eval/rule-metrics
 */

import type { SampleResult } from './metrics.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface RuleQuality {
  readonly ruleId: string;
  readonly matchCount: number;
  readonly tpCount: number;
  readonly fpCount: number;
  readonly categories: readonly string[];
  readonly avgConfidence: number;
}

export interface RuleQualityReport {
  readonly totalRulesEvaluated: number;
  readonly rulesFired: number;
  readonly rulesNeverFired: number;
  readonly topRules: readonly RuleQuality[];
  readonly weakRules: readonly RuleQuality[];
  readonly neverFiredRuleIds: readonly string[];
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

interface RuleAccumulator {
  readonly ruleId: string;
  readonly tp: number;
  readonly fp: number;
  readonly categories: ReadonlySet<string>;
  readonly confidenceSum: number;
  readonly confidenceCount: number;
}

function emptyAccumulator(ruleId: string): RuleAccumulator {
  return {
    ruleId,
    tp: 0,
    fp: 0,
    categories: new Set<string>(),
    confidenceSum: 0,
    confidenceCount: 0,
  };
}

function addSampleToAccumulator(
  acc: RuleAccumulator,
  sample: SampleResult
): RuleAccumulator {
  const isAttack = sample.expectedDetection;
  const newCategories = new Set(acc.categories);
  newCategories.add(sample.category);

  return {
    ruleId: acc.ruleId,
    tp: acc.tp + (isAttack ? 1 : 0),
    fp: acc.fp + (isAttack ? 0 : 1),
    categories: newCategories,
    confidenceSum: acc.confidenceSum + sample.confidence,
    confidenceCount: acc.confidenceCount + 1,
  };
}

function accumulatorToQuality(acc: RuleAccumulator): RuleQuality {
  const matchCount = acc.tp + acc.fp;
  return {
    ruleId: acc.ruleId,
    matchCount,
    tpCount: acc.tp,
    fpCount: acc.fp,
    categories: [...acc.categories].sort(),
    avgConfidence: acc.confidenceCount > 0
      ? acc.confidenceSum / acc.confidenceCount
      : 0,
  };
}

// ---------------------------------------------------------------------------
// Core computation
// ---------------------------------------------------------------------------

/**
 * Compute per-rule quality metrics from eval results.
 *
 * @param results - The sample results from an eval run
 * @param loadedRuleIds - All rule IDs that were loaded in the engine
 * @returns A RuleQualityReport with top, weak, and never-fired rules
 */
export function computeRuleQuality(
  results: readonly SampleResult[],
  loadedRuleIds: readonly string[]
): RuleQualityReport {
  // Build per-rule accumulators from results
  const accumulators = new Map<string, RuleAccumulator>();

  for (const sample of results) {
    for (const ruleId of sample.matchedRules) {
      const existing = accumulators.get(ruleId) ?? emptyAccumulator(ruleId);
      accumulators.set(ruleId, addSampleToAccumulator(existing, sample));
    }
  }

  // Convert accumulators to RuleQuality entries
  const allQualities: readonly RuleQuality[] = [...accumulators.values()]
    .map(accumulatorToQuality);

  // Sort by matchCount descending for top rules
  const sortedByMatch = [...allQualities].sort((a, b) => b.matchCount - a.matchCount);

  // Weak rules: have FP > 0, or matchCount <= 1 (very low contribution)
  const weakRules = [...allQualities]
    .filter((r) => r.fpCount > 0 || r.matchCount <= 1)
    .sort((a, b) => {
      // Sort by fpCount desc first, then matchCount asc
      if (b.fpCount !== a.fpCount) return b.fpCount - a.fpCount;
      return a.matchCount - b.matchCount;
    });

  // Determine never-fired rules
  const firedRuleIds = new Set(accumulators.keys());
  const neverFiredRuleIds = loadedRuleIds
    .filter((id) => !firedRuleIds.has(id))
    .sort();

  return {
    totalRulesEvaluated: loadedRuleIds.length,
    rulesFired: firedRuleIds.size,
    rulesNeverFired: neverFiredRuleIds.length,
    topRules: sortedByMatch,
    weakRules,
    neverFiredRuleIds,
  };
}
