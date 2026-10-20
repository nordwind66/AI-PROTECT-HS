/**
 * Content hashing utility for scan result deduplication and TC verdict cache.
 * @module agent-threat-rules/content-hash
 */

import { createHash } from 'node:crypto';

/** Compute a SHA-256 hex digest of the given content string. */
export function computeContentHash(content: string): string {
  return createHash('sha256').update(content, 'utf8').digest('hex');
}
