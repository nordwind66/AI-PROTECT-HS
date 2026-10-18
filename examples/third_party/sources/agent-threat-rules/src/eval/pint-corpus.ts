/**
 * PINT Benchmark Corpus Loader
 *
 * Reads the PINT-format dataset (JSON with text/category/label/source/language)
 * built from publicly available prompt injection datasets:
 *   - deepset/prompt-injections (HuggingFace)
 *   - Lakera/gandalf_ignore_instructions (HuggingFace)
 *
 * Converts each sample into the CorpusSample interface used by the ATR eval
 * harness, allowing the PINT corpus to be evaluated alongside or instead of
 * the built-in hand-crafted corpus.
 *
 * @module agent-threat-rules/eval/pint-corpus
 */

import { readFileSync } from 'node:fs';
import type { CorpusSample } from './corpus.js';

// ---------------------------------------------------------------------------
// Raw PINT sample shape (as stored in pint-corpus.json)
// ---------------------------------------------------------------------------

interface RawPintSample {
  readonly text: string;
  readonly category: string;
  readonly label: boolean;
  readonly source: string;
  readonly language: string;
}

// ---------------------------------------------------------------------------
// Difficulty assignment
// ---------------------------------------------------------------------------

/**
 * Assign difficulty based on language and category:
 *   - Non-English injections -> 'hard'  (multilingual evasion)
 *   - English injections     -> 'easy'  (standard patterns)
 *   - Benign samples         -> 'medium' (false-positive pressure)
 */
function assignDifficulty(
  sample: RawPintSample
): 'easy' | 'medium' | 'hard' {
  if (!sample.label) {
    return 'medium';
  }
  return sample.language !== 'en' ? 'hard' : 'easy';
}

// ---------------------------------------------------------------------------
// Category mapping
// ---------------------------------------------------------------------------

/**
 * Map raw PINT categories to ATR eval categories.
 * PINT uses: prompt_injection, jailbreak, benign, hard_negatives,
 *            chat, documents, short_input, benign_input, long_input
 */
function mapCategory(raw: string, isInjection: boolean): string {
  if (isInjection) {
    if (raw === 'jailbreak') return 'jailbreak';
    return 'prompt-injection';
  }
  return 'benign';
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Load the PINT benchmark corpus from a JSON file on disk.
 *
 * @param dataPath - Absolute path to pint-corpus.json
 * @returns Readonly array of CorpusSample for use with runEval()
 */
export function loadPintCorpus(dataPath: string): readonly CorpusSample[] {
  const raw: readonly RawPintSample[] = JSON.parse(
    readFileSync(dataPath, 'utf-8')
  );

  const seen = new Set<string>();
  const samples: CorpusSample[] = [];

  for (let i = 0; i < raw.length; i++) {
    const entry = raw[i]!;
    const text = entry.text.trim();

    // Skip empty or duplicate texts
    const key = text.toLowerCase().slice(0, 200);
    if (!text || seen.has(key)) continue;
    seen.add(key);

    // A sample is an attack only when the label field explicitly marks it true.
    // Guard against dataset noise: entries with label=false must never be
    // counted as false negatives regardless of their category field.
    const isAttack = entry.label === true;
    const difficulty = assignDifficulty(entry);
    const category = mapCategory(entry.category, isAttack);

    samples.push({
      id: `pint-${String(i + 1).padStart(4, '0')}`,
      text,
      category,
      expectedDetection: isAttack,
      eventType: 'llm_input',
      tier: 'any',
      difficulty,
      fields: {
        source: entry.source,
        language: entry.language,
        originalCategory: entry.category,
      },
    });
  }

  return samples;
}

/**
 * Get summary statistics for the loaded PINT corpus.
 */
export function getPintCorpusStats(corpus: readonly CorpusSample[]): {
  readonly total: number;
  readonly attacks: number;
  readonly benign: number;
  readonly byCategory: Readonly<Record<string, number>>;
  readonly byDifficulty: Readonly<Record<string, number>>;
  readonly byLanguage: Readonly<Record<string, number>>;
} {
  const byCategory: Record<string, number> = {};
  const byDifficulty: Record<string, number> = {};
  const byLanguage: Record<string, number> = {};

  for (const s of corpus) {
    byCategory[s.category] = (byCategory[s.category] ?? 0) + 1;
    byDifficulty[s.difficulty] = (byDifficulty[s.difficulty] ?? 0) + 1;
    const lang = s.fields?.['language'] ?? 'unknown';
    byLanguage[lang] = (byLanguage[lang] ?? 0) + 1;
  }

  return {
    total: corpus.length,
    attacks: corpus.filter((s) => s.expectedDetection).length,
    benign: corpus.filter((s) => !s.expectedDetection).length,
    byCategory,
    byDifficulty,
    byLanguage,
  };
}
