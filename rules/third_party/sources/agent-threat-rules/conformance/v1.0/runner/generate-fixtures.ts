#!/usr/bin/env tsx
/**
 * Generate ATR Conformance Test Suite v1.0 TP and TN fixtures from the
 * embedded `test_cases` blocks in each rule YAML. Each rule already
 * ships ≥5 TP + ≥5 TN test cases per the SPEC §5.1 contract; this
 * script lifts a deterministic subset of those into standalone
 * conformance fixtures.
 *
 * Strategy: walk rules/<category>/*.yaml in lexicographic order; for
 * each category, take the first N rules (where N is the per-category
 * quota); for each selected rule, take its first TP and first TN test
 * case and write them to fixtures/tp/<rule_id>/{input,expect} and
 * fixtures/tn/<rule_id>/{input,expect}.
 *
 * Idempotent: re-running overwrites generated fixtures but leaves
 * manually authored fixtures untouched (manually authored fixtures
 * use rule IDs already present at generator boot time and are
 * preserved by `--skip-existing`).
 *
 * Usage: tsx conformance/v1.0/runner/generate-fixtures.ts
 */

import { readFileSync, writeFileSync, readdirSync, mkdirSync, existsSync, statSync } from 'node:fs';
import { join, dirname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';
import yaml from 'js-yaml';

const __dirname = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(__dirname, '..', '..', '..');
const RULES_ROOT = join(REPO_ROOT, 'rules');
const FIXTURE_ROOT = join(REPO_ROOT, 'conformance', 'v1.0', 'fixtures');

interface TestCase {
  input: string;
  expected: 'triggered' | 'not_triggered';
  description?: string;
}

interface RuleYaml {
  id: string;
  title: string;
  tags?: { category?: string; scan_target?: string };
  test_cases?: {
    true_positives?: TestCase[];
    true_negatives?: TestCase[];
  };
}

// Per-category quotas summing to ~100 fixtures. Tunable.
const QUOTAS: Record<string, number> = {
  'prompt-injection': 25,
  'agent-manipulation': 20,
  'skill-compromise': 12,
  'context-exfiltration': 12,
  'tool-poisoning': 10,
  'privilege-escalation': 8,
  'model-abuse': 6,
  'excessive-autonomy': 4,
  'model-security': 2,
  'data-poisoning': 1,
};

function loadRule(path: string): RuleYaml | null {
  try {
    const text = readFileSync(path, 'utf8');
    const doc = yaml.load(text) as RuleYaml;
    return doc && typeof doc === 'object' && typeof doc.id === 'string' ? doc : null;
  } catch {
    return null;
  }
}

function listRules(category: string): string[] {
  const dir = join(RULES_ROOT, category);
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => f.endsWith('.yaml') && statSync(join(dir, f)).isFile())
    .sort()
    .map((f) => join(dir, f));
}

function writeFixture(
  category: 'tp' | 'tn',
  ruleId: string,
  scanTarget: string,
  testCase: TestCase,
): boolean {
  const dir = join(FIXTURE_ROOT, category, ruleId);
  if (existsSync(join(dir, 'input.yaml'))) return false;
  mkdirSync(dir, { recursive: true });
  const input: Record<string, string> = {
    scan_target: scanTarget,
    input: testCase.input,
  };
  if (testCase.description) input.rationale = testCase.description;
  writeFileSync(join(dir, 'input.yaml'), yaml.dump(input, { lineWidth: -1 }));
  const expect = {
    outcome: category === 'tp' ? 'match' : 'no_match',
    rule_id: ruleId,
    ...(category === 'tp' ? { min_match_count: 1 } : {}),
  };
  writeFileSync(join(dir, 'expect.json'), JSON.stringify(expect, null, 2) + '\n');
  return true;
}

function main(): void {
  let tpWritten = 0;
  let tnWritten = 0;
  let tpSkipped = 0;
  let tnSkipped = 0;
  for (const [category, quota] of Object.entries(QUOTAS)) {
    let picked = 0;
    for (const path of listRules(category)) {
      if (picked >= quota) break;
      const rule = loadRule(path);
      if (!rule || !rule.test_cases) continue;
      const tps = rule.test_cases.true_positives ?? [];
      const tns = rule.test_cases.true_negatives ?? [];
      if (tps.length === 0 || tns.length === 0) continue;
      const scanTarget = rule.tags?.scan_target ?? 'skill';
      const tpDone = writeFixture('tp', rule.id, scanTarget, tps[0]);
      const tnDone = writeFixture('tn', rule.id, scanTarget, tns[0]);
      if (tpDone) tpWritten++;
      else tpSkipped++;
      if (tnDone) tnWritten++;
      else tnSkipped++;
      picked++;
    }
    console.log(`  ${category}: picked ${picked}/${quota}`);
  }
  console.log(
    `[generate-fixtures] TP: ${tpWritten} written, ${tpSkipped} skipped (existed); TN: ${tnWritten} written, ${tnSkipped} skipped`,
  );
}

main();
