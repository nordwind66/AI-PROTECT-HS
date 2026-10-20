/**
 * Embedding Module -- Tier 2.5 semantic similarity detection.
 *
 * Compares incoming text against pre-computed attack embeddings using
 * cosine similarity. Catches paraphrases, multilingual attacks, and
 * semantic variants that regex cannot detect.
 *
 * Uses all-MiniLM-L6-v2 (384 dimensions, ~22MB, runs locally in JS/WASM).
 * No API calls. Optional dependency: @xenova/transformers.
 *
 * @module agent-threat-rules/modules/embedding
 */

import type { AgentEvent } from '../types.js';
import type { ATRModule, ModuleCondition, ModuleResult } from './index.js';
import {
  VectorStore,
  loadVectorEntries,
  type VectorEntry,
  type SearchResult,
} from '../embedding/vector-store.js';
import type { EmbeddingModel } from '../embedding/model-loader.js';

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

export interface EmbeddingModuleConfig {
  /** Pre-loaded attack vector entries */
  readonly attackVectors?: readonly VectorEntry[];
  /** Path to pre-computed attack-embeddings.json file */
  readonly attackVectorsPath?: string;
  /** Raw JSON data (alternative to file path) */
  readonly attackVectorsData?: readonly {
    id: string;
    vector: number[];
    label: string;
    category: string;
    severity: string;
  }[];
  /** Cosine similarity threshold (default: 0.65) */
  readonly similarityThreshold?: number;
  /** Top-K results to consider (default: 3) */
  readonly topK?: number;
  /** Custom embedding model (default: TransformersJSModel) */
  readonly model?: EmbeddingModel;
}

// ---------------------------------------------------------------------------
// Module
// ---------------------------------------------------------------------------

export class EmbeddingModule implements ATRModule {
  readonly name = 'embedding';
  readonly description = 'Vector similarity detection against known attack embeddings';
  readonly version = '0.1.0';

  readonly functions = [
    {
      name: 'similarity_search',
      description: 'Find nearest known attacks by embedding similarity',
      args: [
        {
          name: 'field',
          type: 'string' as const,
          required: false,
          description: 'Event field to embed (default: content)',
        },
        {
          name: 'threshold',
          type: 'number' as const,
          required: false,
          description: 'Similarity threshold override',
        },
      ],
    },
  ];

  private store: VectorStore;
  private model: EmbeddingModel | null;
  private readonly threshold: number;
  private readonly topK: number;
  private initialized = false;

  constructor(private readonly config: EmbeddingModuleConfig = {}) {
    this.threshold = config.similarityThreshold ?? 0.65;
    this.topK = config.topK ?? 3;
    this.model = config.model ?? null;
    this.store = new VectorStore(config.attackVectors);
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Load attack vectors from data
    if (this.config.attackVectorsData) {
      const entries = loadVectorEntries(this.config.attackVectorsData);
      this.store = this.store.withEntries(entries);
    }

    // Load attack vectors from file
    if (this.config.attackVectorsPath) {
      try {
        const { readFileSync } = await import('node:fs');
        const data = JSON.parse(readFileSync(this.config.attackVectorsPath, 'utf-8'));
        const entries = loadVectorEntries(data);
        this.store = this.store.withEntries(entries);
      } catch {
        // File not found = no pre-computed vectors, continue without them
      }
    }

    // Load model if not provided
    if (!this.model) {
      try {
        const { TransformersJSModel } = await import('../embedding/model-loader.js');
        this.model = new TransformersJSModel();
        await this.model.initialize();
      } catch (err) {
        // Model not available = module degrades gracefully
        const msg = err instanceof Error ? err.message : String(err);
        console.warn(`[embedding] Model not available: ${msg}. Module disabled.`);
        this.model = null;
      }
    }

    this.initialized = true;
  }

  async evaluate(event: AgentEvent, condition: ModuleCondition): Promise<ModuleResult> {
    if (!this.model || this.store.size() === 0) {
      return { matched: false, value: 0, description: 'Embedding module not initialized' };
    }

    // Extract text to embed
    const field = (condition.args?.field as string) ?? 'content';
    const text =
      field === 'content'
        ? event.content
        : event.fields?.[field] ?? event.content;

    if (!text || text.length < 5) {
      return { matched: false, value: 0, description: 'Input too short for embedding' };
    }

    // Truncate to avoid excessive token usage
    const truncated = text.slice(0, 512);

    try {
      // Encode input
      const queryVec = await this.model.encode(truncated);

      // Search for similar attacks
      const threshold = (condition.args?.threshold as number) ?? this.threshold;
      const results = this.store.search(queryVec, this.topK, threshold);

      if (results.length === 0) {
        return { matched: false, value: 0, description: 'No similar attacks found' };
      }

      const top = results[0]!;
      return {
        matched: true,
        value: top.similarity,
        description: `Similar to known attack: "${top.entry.label}" (${top.entry.category}, similarity: ${top.similarity.toFixed(3)})`,
      };
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      return { matched: false, value: 0, description: `Embedding error: ${msg}` };
    }
  }

  /** Get search results with full details (for debugging/testing) */
  async searchDetailed(text: string, threshold?: number): Promise<readonly SearchResult[]> {
    if (!this.model || this.store.size() === 0) return [];
    const queryVec = await this.model.encode(text.slice(0, 512));
    return this.store.search(queryVec, this.topK, threshold ?? this.threshold);
  }

  async destroy(): Promise<void> {
    this.model = null;
    this.initialized = false;
  }

  /** Check if module is operational */
  isAvailable(): boolean {
    return this.initialized && this.model !== null && this.store.size() > 0;
  }
}
