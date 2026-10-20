/**
 * atr_scan_skill MCP tool - Scan SKILL.md content for threats
 *
 * Uses scanSkillFull() which only runs skill-targeted rules (scan_target: skill)
 * to avoid false positives from MCP-oriented rules.
 *
 * @module agent-threat-rules/mcp-tools/scan-skill
 */

import type { ATREngine } from '../engine.js';

const SEVERITY_ORDER: Record<string, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export async function handleScanSkill(
  engine: ATREngine,
  args: Record<string, unknown>,
): Promise<{
  content: Array<{ type: string; text: string }>;
  isError?: boolean;
}> {
  const MAX_CONTENT_LENGTH = 1_000_000; // 1MB for SKILL.md files

  const content = args['content'];
  if (typeof content !== 'string' || content.trim().length === 0) {
    return {
      content: [{ type: 'text', text: 'Error: "content" is required and must be a non-empty string.' }],
      isError: true,
    };
  }
  if (content.length > MAX_CONTENT_LENGTH) {
    return {
      content: [{ type: 'text', text: `Error: content exceeds maximum size of ${MAX_CONTENT_LENGTH} characters.` }],
      isError: true,
    };
  }

  const minSeverity = ((args['min_severity'] as string) ?? 'medium').toLowerCase();
  if (!(minSeverity in SEVERITY_ORDER)) {
    return {
      content: [{ type: 'text', text: `Error: Invalid min_severity "${minSeverity}". Valid: informational, low, medium, high, critical` }],
      isError: true,
    };
  }

  const fileName = typeof args['file_name'] === 'string' ? args['file_name'] : undefined;
  const minIdx = SEVERITY_ORDER[minSeverity] ?? 0;

  const scanResult = engine.scanSkillFull(content, fileName);

  const filtered = scanResult.matches.filter(
    (m) => (SEVERITY_ORDER[m.rule.severity] ?? 0) >= minIdx,
  );

  const result = {
    scan_type: scanResult.scan_type,
    content_hash: scanResult.content_hash,
    file_name: fileName,
    threats_found: filtered.length,
    scan_timestamp: scanResult.timestamp,
    rules_loaded: scanResult.rules_loaded,
    matches: filtered.map((m) => ({
      rule_id: m.rule.id,
      rule_version: m.rule.rule_version,
      title: m.rule.title,
      severity: m.rule.severity,
      category: m.rule.tags.category,
      confidence: Math.round(m.confidence * 100),
      description: m.rule.description,
      matched_patterns: m.matchedPatterns,
      recommended_actions: m.rule.response.actions,
    })),
  };

  return {
    content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
  };
}
