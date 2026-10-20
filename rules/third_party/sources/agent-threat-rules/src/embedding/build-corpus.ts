#!/usr/bin/env npx tsx
/**
 * Build attack embedding corpus from ATR rule test cases.
 *
 * Reads all stable ATR rules, extracts true_positive test cases,
 * encodes them through all-MiniLM-L6-v2, and saves as JSON.
 *
 * Usage:
 *   npx tsx src/embedding/build-corpus.ts
 *
 * Output:
 *   data/attack-embeddings.json
 */

import { readFileSync, writeFileSync, mkdirSync, readdirSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import * as yaml from 'js-yaml';

const RULES_DIR = resolve(join(import.meta.dirname ?? '.', '..', '..', 'rules'));
const OUTPUT_PATH = resolve(join(import.meta.dirname ?? '.', '..', '..', 'data', 'attack-embeddings.json'));

interface RuleTestCase {
  input?: string;
  content?: string;
  user_input?: string;
  tool_response?: string;
  tool_description?: string;
  tool_args?: string;
  expected: string;
  description?: string;
}

interface ATRRuleYAML {
  id: string;
  title: string;
  severity: string;
  tags?: { category?: string };
  test_cases?: {
    true_positives?: RuleTestCase[];
  };
}

async function main() {
  console.log('Building attack embedding corpus...');
  console.log(`Rules dir: ${RULES_DIR}`);

  // Load model
  console.log('Loading embedding model (first run downloads ~22MB)...');
  const { TransformersJSModel } = await import('./model-loader.js');
  const model = new TransformersJSModel();
  await model.initialize();
  console.log('Model loaded.');

  // Collect all true_positive texts from rules
  const attacks: Array<{ id: string; text: string; category: string; severity: string; ruleTitle: string }> = [];

  function walkDir(dir: string): string[] {
    const files: string[] = [];
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const fullPath = join(dir, entry.name);
      if (entry.isDirectory()) {
        files.push(...walkDir(fullPath));
      } else if (entry.name.endsWith('.yaml') || entry.name.endsWith('.yml')) {
        files.push(fullPath);
      }
    }
    return files;
  }

  const ruleFiles = walkDir(RULES_DIR);
  console.log(`Found ${ruleFiles.length} rule files.`);

  for (const file of ruleFiles) {
    try {
      const content = readFileSync(file, 'utf-8');
      const rule = yaml.load(content) as ATRRuleYAML;
      if (!rule?.id || !rule?.test_cases?.true_positives) continue;

      for (const tp of rule.test_cases.true_positives) {
        const text = tp.input ?? tp.content ?? tp.user_input ?? tp.tool_response ?? tp.tool_description ?? tp.tool_args;
        if (!text || text.length < 10) continue;

        attacks.push({
          id: rule.id,
          text: text.slice(0, 512),
          category: rule.tags?.category ?? 'unknown',
          severity: rule.severity ?? 'medium',
          ruleTitle: rule.title ?? rule.id,
        });
      }
    } catch {
      // Skip unparseable rules
    }
  }

  console.log(`Extracted ${attacks.length} attack payloads from ${ruleFiles.length} rules.`);

  // Deduplicate by text
  const seen = new Set<string>();
  const unique = attacks.filter((a) => {
    if (seen.has(a.text)) return false;
    seen.add(a.text);
    return true;
  });
  console.log(`Unique payloads: ${unique.length}`);

  // Encode all payloads
  console.log('Encoding payloads...');
  const output: Array<{
    id: string;
    text: string;
    vector: number[];
    label: string;
    category: string;
    severity: string;
  }> = [];

  for (let i = 0; i < unique.length; i++) {
    const a = unique[i]!;
    process.stdout.write(`\r  [${i + 1}/${unique.length}] ${a.id}`);
    const vec = await model.encode(a.text);
    output.push({
      id: `${a.id}-tp${i}`,
      text: a.text,
      vector: Array.from(vec),
      label: `${a.ruleTitle}: ${a.text.slice(0, 80)}`,
      category: a.category,
      severity: a.severity,
    });
  }
  console.log('\n');

  // Save
  mkdirSync(join(OUTPUT_PATH, '..'), { recursive: true });
  writeFileSync(OUTPUT_PATH, JSON.stringify(output, null, 2));
  console.log(`Saved ${output.length} embeddings to ${OUTPUT_PATH}`);
  console.log(`File size: ${(readFileSync(OUTPUT_PATH).length / 1024).toFixed(0)} KB`);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});
