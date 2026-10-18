/**
 * Verdict computation from ATR rule matches.
 *
 * Pure functions that determine the outcome (allow/ask/deny)
 * based on severity, confidence, and auto-response thresholds.
 *
 * @module agent-threat-rules/verdict
 */

import type {
  ATRMatch,
  ATRSeverity,
  ATRAction,
  ATRVerdict,
  VerdictOutcome,
} from './types.js';

/** Severity rank from most severe (0) to least severe (4) */
export const SEVERITY_RANK: Readonly<Record<ATRSeverity, number>> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
};

/**
 * Check whether auto-response is enabled for a matched rule.
 * The auto_response_threshold field on ATRResponse indicates the
 * minimum confidence level at which the action should be taken
 * automatically (without human approval).
 */
export function isAutoResponseEnabled(
  match: ATRMatch
): boolean {
  const threshold = match.rule.response.auto_response_threshold;
  if (!threshold) return false;

  const thresholdMap: Record<string, number> = {
    high: 0.9,
    medium: 0.7,
    low: 0.5,
  };

  const requiredConfidence = thresholdMap[threshold];
  if (requiredConfidence === undefined) return false;

  return match.confidence >= requiredConfidence;
}

/**
 * Determine the verdict outcome based on severity and confidence.
 *
 * Decision matrix:
 *   - critical severity           -> deny
 *   - high severity, conf >= 0.8  -> deny
 *   - high severity, conf < 0.8   -> ask
 *   - medium severity, conf >= 0.6 -> ask
 *   - everything else             -> allow
 */
function determineOutcome(
  severity: ATRSeverity,
  confidence: number
): VerdictOutcome {
  if (severity === 'critical') {
    return 'deny';
  }
  if (severity === 'high') {
    return confidence >= 0.8 ? 'deny' : 'ask';
  }
  if (severity === 'medium' && confidence >= 0.6) {
    return 'ask';
  }
  return 'allow';
}

/**
 * Collect unique actions from all matched rules, preserving order
 * of first appearance.
 */
function collectUniqueActions(
  matches: readonly ATRMatch[]
): readonly ATRAction[] {
  const seen = new Set<ATRAction>();
  const actions: ATRAction[] = [];

  for (const match of matches) {
    for (const action of match.rule.response.actions) {
      if (!seen.has(action)) {
        seen.add(action);
        actions.push(action);
      }
    }
  }

  return Object.freeze(actions);
}

/**
 * Build a human-readable reason string from the highest severity match.
 */
function buildReason(
  highestMatch: ATRMatch | undefined,
  outcome: VerdictOutcome,
  matchCount: number
): string {
  if (!highestMatch) {
    return 'No rules matched.';
  }

  const { rule, confidence } = highestMatch;
  const pct = Math.round(confidence * 100);

  return (
    `${outcome.toUpperCase()}: ${rule.title} ` +
    `[${rule.severity}/${pct}% confidence] ` +
    `(${matchCount} rule${matchCount === 1 ? '' : 's'} matched)`
  );
}

/**
 * Compute a verdict from an array of ATR matches.
 *
 * This is a pure function -- no side effects, no mutation.
 * Returns a frozen ATRVerdict object.
 */
export function computeVerdict(
  matches: readonly ATRMatch[]
): ATRVerdict {
  if (matches.length === 0) {
    return Object.freeze({
      outcome: 'allow' as const,
      reason: 'No rules matched.',
      matchCount: 0,
      highestSeverity: null,
      highestConfidence: 0,
      actions: Object.freeze([]),
      matches: Object.freeze([]),
      timestamp: new Date().toISOString(),
    });
  }

  // Matches are already sorted by the engine (severity desc, confidence desc).
  // The first match has the highest severity.
  const highestMatch = matches[0]!;
  const highestSeverity = highestMatch.rule.severity;
  const highestConfidence = highestMatch.confidence;

  const outcome = determineOutcome(highestSeverity, highestConfidence);
  const actions = collectUniqueActions(matches);
  const reason = buildReason(highestMatch, outcome, matches.length);

  return Object.freeze({
    outcome,
    reason,
    matchCount: matches.length,
    highestSeverity,
    highestConfidence,
    actions,
    matches: Object.freeze([...matches]),
    timestamp: new Date().toISOString(),
  });
}
