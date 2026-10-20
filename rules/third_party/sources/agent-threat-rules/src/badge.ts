/**
 * ATR Badge Generator
 *
 * Generates shields.io-compatible SVG badges and JSON endpoints
 * for ATR scan results.
 *
 * Badge states:
 *   - Green:  "ATR Scanned - No Issues" (scan passed, no findings)
 *   - Yellow: "ATR Scanned - Issues Found" (scan found potential threats)
 *   - Red:    "ATR Scanned - Critical" (critical threats detected)
 *   - Gray:   "Not Yet Scanned" (no scan data available)
 *
 * @module agent-threat-rules/badge
 */

import { readFileSync } from 'node:fs';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BadgeData {
  readonly schemaVersion: 1;
  readonly label: string;
  readonly message: string;
  readonly color: string;
  readonly namedLogo?: string;
  readonly logoSvg?: string;
}

export type BadgeStatus = 'clean' | 'issues' | 'critical' | 'unknown';

export interface ScanSummary {
  readonly packageName: string;
  readonly version?: string;
  readonly scannedAt?: string;
  readonly riskLevel: string;
  readonly riskScore: number;
  readonly findings: {
    readonly critical: number;
    readonly high: number;
    readonly medium: number;
    readonly low: number;
  };
}

// ---------------------------------------------------------------------------
// Badge colors
// ---------------------------------------------------------------------------

const BADGE_COLORS: Record<BadgeStatus, string> = {
  clean: '#2ea44f',     // GitHub green
  issues: '#dfb317',    // Warning yellow
  critical: '#e05d44',  // Alert red
  unknown: '#9f9f9f',   // Gray
};

// ---------------------------------------------------------------------------
// Determine badge status from scan data
// ---------------------------------------------------------------------------

export function determineBadgeStatus(summary: ScanSummary): BadgeStatus {
  // Check ATR rule findings first
  if (summary.findings.critical > 0) return 'critical';
  if (summary.findings.high > 0) return 'critical';
  if (summary.findings.medium > 0) return 'issues';
  if (summary.findings.low > 0) return 'issues';

  // Fall back to overall risk assessment (from code analysis, supply chain, etc.)
  const level = summary.riskLevel.toUpperCase();
  if (level === 'CRITICAL' || level === 'HIGH') return 'critical';
  if (level === 'MEDIUM') return 'issues';
  if (level === 'LOW') return 'issues';

  return 'clean';
}

// ---------------------------------------------------------------------------
// Generate shields.io endpoint JSON
// ---------------------------------------------------------------------------

export function generateBadgeEndpoint(summary: ScanSummary | null): BadgeData {
  if (!summary) {
    return {
      schemaVersion: 1,
      label: 'ATR',
      message: 'Not Yet Scanned',
      color: BADGE_COLORS.unknown,
    };
  }

  const status = determineBadgeStatus(summary);

  const totalFindings = summary.findings.critical + summary.findings.high + summary.findings.medium + summary.findings.low;

  const messages: Record<BadgeStatus, string> = {
    clean: 'Scanned - No Issues',
    issues: totalFindings > 0
      ? `Scanned - ${totalFindings} Issue${totalFindings > 1 ? 's' : ''}`
      : `Scanned - ${summary.riskLevel}`,
    critical: totalFindings > 0
      ? `Scanned - ${summary.findings.critical + summary.findings.high} Critical`
      : `Scanned - ${summary.riskLevel}`,
    unknown: 'Not Yet Scanned',
  };

  return {
    schemaVersion: 1,
    label: 'ATR',
    message: messages[status],
    color: BADGE_COLORS[status],
  };
}

// ---------------------------------------------------------------------------
// Generate standalone SVG badge
// ---------------------------------------------------------------------------

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

function measureText(text: string): number {
  // Approximate character width for Verdana 11px (shields.io standard)
  return text.length * 6.8 + 10;
}

export function generateBadgeSvg(summary: ScanSummary | null): string {
  const data = generateBadgeEndpoint(summary);
  const label = escapeXml(data.label);
  const message = escapeXml(data.message);
  const color = data.color;

  const labelWidth = measureText(label);
  const messageWidth = measureText(message);
  const totalWidth = labelWidth + messageWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="${totalWidth}" height="20" role="img" aria-label="${label}: ${message}">
  <title>${label}: ${message}</title>
  <linearGradient id="s" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <clipPath id="r">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </clipPath>
  <g clip-path="url(#r)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${messageWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#s)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" text-rendering="geometricPrecision" font-size="110">
    <text aria-hidden="true" x="${labelWidth * 5}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">${label}</text>
    <text x="${labelWidth * 5}" y="140" transform="scale(.1)" fill="#fff">${label}</text>
    <text aria-hidden="true" x="${(labelWidth + messageWidth / 2) * 10}" y="150" fill="#010101" fill-opacity=".3" transform="scale(.1)">${message}</text>
    <text x="${(labelWidth + messageWidth / 2) * 10}" y="140" transform="scale(.1)" fill="#fff">${message}</text>
  </g>
</svg>`;
}

// ---------------------------------------------------------------------------
// Load scan result from audit data file
// ---------------------------------------------------------------------------

export function lookupPackageScan(
  auditDataPath: string,
  packageName: string,
): ScanSummary | null {
  try {
    const data = JSON.parse(readFileSync(auditDataPath, 'utf-8'));

    const results: unknown[] = data.results ?? [];
    const entry = results.find((r: any) => r.package === packageName) as any;

    if (!entry) return null;

    const atrMatches: any[] = entry.atrMatches ?? [];
    const findings = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const m of atrMatches) {
      const sev = (m.severity ?? m.rule?.severity ?? 'low').toLowerCase();
      if (sev in findings) {
        findings[sev as keyof typeof findings]++;
      }
    }

    return {
      packageName: entry.package,
      version: entry.version,
      scannedAt: entry.auditedAt ?? data.auditedAt,
      riskLevel: entry.riskLevel ?? 'UNKNOWN',
      riskScore: entry.riskScore ?? 0,
      findings,
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Generate markdown badge snippet
// ---------------------------------------------------------------------------

export function generateBadgeMarkdown(
  packageName: string,
  repoUrl: string = 'https://github.com/Agent-Threat-Rule/agent-threat-rules',
): string {
  // Static badge URL using shields.io
  const encodedName = encodeURIComponent(packageName);
  return `[![ATR Scanned](https://img.shields.io/badge/ATR-Scanned-2ea44f?style=flat-square)](${repoUrl})`;
}
