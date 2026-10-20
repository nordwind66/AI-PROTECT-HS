/**
 * Shared capability extraction from text content.
 *
 * Used by both SkillFingerprintStore (behavioral drift detection)
 * and InvariantChecker (manifest enforcement).
 *
 * Regex-based, no LLM needed. Analyzes first 10KB to prevent ReDoS.
 *
 * @module agent-threat-rules/capability-extractor
 */

// ---------------------------------------------------------------------------
// Pattern detectors
// ---------------------------------------------------------------------------

export const FS_WRITE_PATTERN =
  /(?:write(?:File)?|appendFile|fs\.write|truncate|mkdir|rmdir|unlink|rm\s+-)/i;
export const FS_READ_PATTERN =
  /(?:read(?:File)?|readdir|stat|access|exists|glob|find\s)/i;
export const FS_DELETE_PATTERN =
  /(?:unlink|rm\s+-rf|delete(?:File)?|removeDir|rmdir)/i;

export const NETWORK_PATTERN =
  /(?:https?:\/\/|fetch|curl|wget|axios|http\.request|net\.connect|socket)[\s('"]*([a-zA-Z0-9.-]+(?:\.[a-zA-Z]{2,}))/i;

export const ENV_PATTERN =
  /(?:process\.env|os\.environ|getenv|System\.getenv)\[?['"(]?([A-Z_][A-Z0-9_]*)/i;
export const ENV_INLINE_PATTERN = /\$\{?([A-Z_][A-Z0-9_]{2,})\}?/g;

export const EXEC_PATTERN =
  /(?:child_process|spawn|exec(?:File)?|system\(|popen|subprocess|shell_exec|os\.system)\s*\(\s*['"(]?([^\s'")\]]{1,80})/i;

export const EXFIL_PATTERN =
  /(?:base64|btoa|encode|compress|deflate|gzip).*(?:http|fetch|curl|send|post|upload)/i;
export const REDIRECT_PATTERN =
  /(?:redirect|forward|proxy|tunnel)\s+(?:to\s+)?(?:https?:\/\/)/i;

/** Path extraction: find filesystem paths referenced in text (min 2 segments to reduce noise) */
export const PATH_PATTERN =
  /(?:["'`]|^|\s)(\/(?:[\w.-]+\/){1,}[\w.-]+)/gm;

/** Common benign paths that appear in docs/version strings -- skip these */
const BENIGN_PATH_PREFIXES = [
  '/usr/bin/', '/usr/lib/', '/usr/local/',
  '/node_modules/', '/dist/', '/build/',
  '/v1/', '/v2/', '/api/',
] as const;

/** Config file modification patterns */
export const CONFIG_MOD_PATTERN =
  /(?:\.mcp\.json|\.claude\/|\.cursor\/|mcp-config|settings\.json|\.env(?:\.\w+)?)/i;

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

export interface ExtractedCapabilities {
  readonly filesystemOps: readonly string[];
  readonly filesystemPaths: readonly string[];
  readonly networkTargets: readonly string[];
  readonly envAccesses: readonly string[];
  readonly processExecs: readonly string[];
  readonly outputPatterns: readonly string[];
  readonly configModifications: boolean;
}

/** Classify text content into behavioral capabilities */
export function extractCapabilities(text: string): ExtractedCapabilities {
  const result = {
    filesystemOps: [] as string[],
    filesystemPaths: [] as string[],
    networkTargets: [] as string[],
    envAccesses: [] as string[],
    processExecs: [] as string[],
    outputPatterns: [] as string[],
    configModifications: false,
  };

  if (!text || text.length === 0) return result;

  // Limit analysis to first 10KB to prevent ReDoS
  const safeText = text.slice(0, 10_240);

  // Filesystem operations
  if (FS_WRITE_PATTERN.test(safeText)) result.filesystemOps.push('write');
  if (FS_READ_PATTERN.test(safeText)) result.filesystemOps.push('read');
  if (FS_DELETE_PATTERN.test(safeText)) result.filesystemOps.push('delete');

  // Filesystem paths (filter out benign paths from docs/version strings)
  for (const m of safeText.matchAll(PATH_PATTERN)) {
    const path = m[1];
    if (!path || result.filesystemPaths.includes(path)) continue;
    const isBenign = BENIGN_PATH_PREFIXES.some((p) => path.startsWith(p));
    if (!isBenign) {
      result.filesystemPaths.push(path);
    }
  }

  // Network targets
  const netMatch = safeText.match(NETWORK_PATTERN);
  if (netMatch?.[1]) result.networkTargets.push(netMatch[1]);

  // Environment variable accesses
  const envMatch = safeText.match(ENV_PATTERN);
  if (envMatch?.[1]) result.envAccesses.push(envMatch[1]);
  for (const m of safeText.matchAll(ENV_INLINE_PATTERN)) {
    if (m[1] && !result.envAccesses.includes(m[1])) {
      result.envAccesses.push(m[1]);
    }
  }

  // Process executions
  const execMatch = safeText.match(EXEC_PATTERN);
  if (execMatch?.[1]) result.processExecs.push(execMatch[1]);

  // Output patterns
  if (EXFIL_PATTERN.test(safeText)) result.outputPatterns.push('exfiltration');
  if (REDIRECT_PATTERN.test(safeText)) result.outputPatterns.push('redirect');

  // Config modifications
  result.configModifications = CONFIG_MOD_PATTERN.test(safeText);

  return result;
}
