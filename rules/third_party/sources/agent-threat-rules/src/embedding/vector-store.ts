/**
 * In-memory vector store with cosine similarity search.
 *
 * Stores pre-computed attack embeddings and finds nearest neighbors
 * for incoming text. Sub-millisecond for ~2000 vectors at 384 dimensions.
 *
 * @module agent-threat-rules/embedding/vector-store
 */

import type { ATRSeverity } from '../types.js';

export interface VectorEntry {
  readonly id: string;
  readonly vector: Float32Array;
  readonly label: string;
  readonly category: string;
  readonly severity: ATRSeverity;
}

export interface SearchResult {
  readonly entry: VectorEntry;
  readonly similarity: number;
}

export class VectorStore {
  private readonly entries: readonly VectorEntry[];

  constructor(entries?: readonly VectorEntry[]) {
    this.entries = entries ?? [];
  }

  /** Create new store with additional entries (immutable) */
  withEntries(newEntries: readonly VectorEntry[]): VectorStore {
    return new VectorStore([...this.entries, ...newEntries]);
  }

  /**
   * Find top-K nearest neighbors by cosine similarity.
   * Only returns results above the threshold.
   */
  search(query: Float32Array, topK: number = 3, threshold: number = 0.82): readonly SearchResult[] {
    if (this.entries.length === 0) return [];

    const results: SearchResult[] = [];

    for (const entry of this.entries) {
      const sim = cosineSimilarity(query, entry.vector);
      if (sim >= threshold) {
        results.push({ entry, similarity: sim });
      }
    }

    // Sort by similarity descending, take top K
    results.sort((a, b) => b.similarity - a.similarity);
    return results.slice(0, topK);
  }

  size(): number {
    return this.entries.length;
  }
}

/**
 * Cosine similarity between two vectors.
 * Returns value between -1 and 1 (1 = identical direction).
 */
function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length) return 0;

  let dot = 0;
  let magA = 0;
  let magB = 0;

  for (let i = 0; i < a.length; i++) {
    dot += a[i]! * b[i]!;
    magA += a[i]! * a[i]!;
    magB += b[i]! * b[i]!;
  }

  const denom = Math.sqrt(magA) * Math.sqrt(magB);
  if (denom === 0) return 0;

  return dot / denom;
}

/** Load pre-computed embeddings from JSON */
export function loadVectorEntries(
  data: readonly { id: string; vector: number[]; label: string; category: string; severity: string }[]
): VectorEntry[] {
  return data.map((d) => ({
    id: d.id,
    vector: new Float32Array(d.vector),
    label: d.label,
    category: d.category,
    severity: (d.severity || 'medium') as ATRSeverity,
  }));
}
