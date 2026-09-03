import crypto from 'crypto';
import type {
  FindingCategory,
  FindingSeverity,
  ScanSummary,
  SemgrepRawMatch,
  SemgrepRawOutput,
} from '@/types';

export interface NormalizedFindingInput {
  scanId: string;
  userId: string;
  scanner: 'semgrep';
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  file: string;
  line: number;
  endLine?: number;
  column?: number;
  endColumn?: number;
  codeSnippet?: string;
  vulnerabilityId: string;
  remediation?: string;
  fingerprint: string;
  metadata?: Record<string, unknown>;
}

export interface NormalizationResult {
  findings: NormalizedFindingInput[];
  summary: ScanSummary;
  rawMatchesCount: number;
  dedupedCount: number;
}

/**
 * Normalizes relative file paths from container (/src/path/to/file -> path/to/file).
 */
export function normalizeFilePath(filePath: string): string {
  let normalized = filePath.replace(/\\/g, '/');

  // Strip leading /src/ or src/
  if (normalized.startsWith('/src/')) {
    normalized = normalized.substring(5);
  } else if (normalized.startsWith('src/') && normalized.length > 4) {
    // If it literally started with /src inside container
  } else if (normalized.startsWith('/')) {
    normalized = normalized.substring(1);
  }

  return normalized;
}

/**
 * Maps Semgrep severity and metadata to SafeRepo's 5-level severity model.
 */
export function mapSemgrepSeverity(
  rawSeverity: string,
  metadata?: Record<string, unknown>
): FindingSeverity {
  const upper = rawSeverity.toUpperCase();
  const cwe = metadata?.cwe ? String(metadata.cwe) : '';
  const owasp = metadata?.owasp ? String(metadata.owasp) : '';

  if (upper === 'ERROR') {
    // High-impact critical vulnerabilities (RCE, SQLi, Command Injection)
    if (
      cwe.includes('CWE-78') || // OS Command Injection
      cwe.includes('CWE-89') || // SQL Injection
      cwe.includes('CWE-95') || // Eval Injection
      owasp.includes('A03:2021') // Injection
    ) {
      return 'critical';
    }
    return 'high';
  }

  if (upper === 'WARNING') {
    return 'medium';
  }

  if (upper === 'INFO') {
    return 'low';
  }

  return 'info';
}

/**
 * Generates a title from Semgrep rule check_id.
 */
export function generateFindingTitle(checkId: string, message: string): string {
  const parts = checkId.split('.');
  const lastPart = parts[parts.length - 1] ?? checkId;

  // Convert kebab/snake case to Title Case
  const formatted = lastPart
    .replace(/[-_]/g, ' ')
    .replace(/\b\w/g, (char) => char.toUpperCase());

  if (formatted.length > 3) {
    return formatted;
  }

  // Fallback to first sentence of message
  const firstSentence = message.split('.')[0]?.trim();
  if (firstSentence && firstSentence.length <= 80) {
    return firstSentence;
  }

  return checkId;
}

/**
 * Generates a deterministic SHA-256 deduplication fingerprint.
 */
export function generateFindingFingerprint(
  scanner: string,
  ruleId: string,
  normalizedFile: string,
  line: number,
  message: string
): string {
  const raw = `${scanner}:${ruleId}:${normalizedFile}:${line}:${message.trim()}`;
  return crypto.createHash('sha256').update(raw).digest('hex');
}

/**
 * Normalizes raw Semgrep output into SafeRepo's unified finding schema.
 */
export function normalizeSemgrepOutput(
  scanId: string,
  userId: string,
  rawOutput: SemgrepRawOutput | string,
  maxFindings = 5000
): NormalizationResult {
  let parsed: SemgrepRawOutput;

  if (typeof rawOutput === 'string') {
    try {
      parsed = JSON.parse(rawOutput) as SemgrepRawOutput;
    } catch {
      throw new Error('Failed to parse Semgrep JSON output');
    }
  } else {
    parsed = rawOutput;
  }

  const results: SemgrepRawMatch[] = parsed.results || [];
  const findingsMap = new Map<string, NormalizedFindingInput>();

  for (const match of results) {
    if (findingsMap.size >= maxFindings) {
      break;
    }

    const file = normalizeFilePath(match.path);
    const ruleId = match.check_id;
    const message = match.extra?.message || 'No description provided';
    const line = match.start?.line ?? 1;
    const fingerprint = generateFindingFingerprint('semgrep', ruleId, file, line, message);

    // Deduplicate within the same scan
    if (findingsMap.has(fingerprint)) {
      continue;
    }

    const severity = mapSemgrepSeverity(match.extra?.severity || 'INFO', match.extra?.metadata);
    const title = generateFindingTitle(ruleId, message);

    const remediation =
      (match.extra?.metadata?.remediation as string | undefined) ||
      match.extra?.fix ||
      undefined;

    findingsMap.set(fingerprint, {
      scanId,
      userId,
      scanner: 'semgrep',
      category: 'sast',
      severity,
      title,
      description: message,
      file,
      line,
      endLine: match.end?.line,
      column: match.start?.col,
      endColumn: match.end?.col,
      codeSnippet: match.extra?.lines?.trim(),
      vulnerabilityId: ruleId,
      remediation,
      fingerprint,
      metadata: match.extra?.metadata,
    });
  }

  const findings = Array.from(findingsMap.values());

  const summary: ScanSummary = {
    total: findings.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const finding of findings) {
    summary[finding.severity]++;
  }

  return {
    findings,
    summary,
    rawMatchesCount: results.length,
    dedupedCount: findings.length,
  };
}
