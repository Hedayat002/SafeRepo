import crypto from 'crypto';
import type {
  DependencyEcosystem,
  FindingCategory,
  FindingScanner,
  FindingSeverity,
  ScanSummary,
  SemgrepRawMatch,
  SemgrepRawOutput,
} from '@/types';
import { parseTrivyJsonOutput, type TrivyVulnerabilityFinding } from './trivy';
import type { OsvVulnerabilityFinding } from './osv';

export interface NormalizedFindingInput {
  scanId: string;
  userId: string;
  scanner: FindingScanner;
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
  package?: string;
  packageVersion?: string;
  fixedVersion?: string;
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

export interface NormalizeDependencyFindingsOptions {
  trivyFindings?: TrivyVulnerabilityFinding[] | string;
  osvFindings?: OsvVulnerabilityFinding[] | string;
  defaultEcosystem?: DependencyEcosystem;
  maxFindings?: number;
}

/**
 * Severity ranking map: critical (5) > high (4) > medium (3) > low (2) > info (1).
 */
export const SEVERITY_RANK: Record<FindingSeverity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

// ============================================================================
// Phase 03: Semgrep Normalization & Fingerprinting (Preserved Unmodified)
// ============================================================================

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
 * Generates a deterministic SHA-256 deduplication fingerprint for SAST findings.
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

// ============================================================================
// Phase 04: Dependency Finding Normalization & Cross-Scanner Deduplication
// ============================================================================

/**
 * Resolves a canonical vulnerability ID deterministically:
 * 1. Trims whitespace and normalizes case.
 * 2. If primary ID is a CVE matching /^CVE-\d{4}-\d+$/i, returns uppercase primary ID.
 * 3. Otherwise inspects aliases matching /^CVE-\d{4}-\d+$/i and selects the first sorted CVE alias (uppercase).
 * 4. Otherwise returns normalized primary ID if present.
 * 5. Otherwise returns the first sorted normalized alias if present.
 * 6. Fallback to 'UNKNOWN'.
 */
export function resolveCanonicalVulnerabilityId(
  primaryId?: string | null,
  aliases: string[] = []
): string {
  const trimmedPrimary = primaryId?.trim() ?? '';
  const cveRegex = /^CVE-\d{4}-\d+$/i;

  // 1. If primary ID is a CVE, use it
  if (cveRegex.test(trimmedPrimary)) {
    return trimmedPrimary.toUpperCase();
  }

  // 2. Otherwise inspect aliases for CVEs
  const trimmedAliases = aliases
    .filter((a): a is string => typeof a === 'string')
    .map((a) => a.trim())
    .filter(Boolean);

  const cveAliases = trimmedAliases
    .filter((id) => cveRegex.test(id))
    .map((id) => id.toUpperCase());

  if (cveAliases.length > 0) {
    // Deterministic selection: sort and pick the first
    cveAliases.sort((a, b) => a.localeCompare(b));
    return cveAliases[0]!;
  }

  // 3. If no CVE exists, use normalized primary ID if non-empty
  if (trimmedPrimary) {
    return trimmedPrimary.toUpperCase();
  }

  // 4. If primary ID is absent, use first deterministic normalized alias
  if (trimmedAliases.length > 0) {
    const sortedAliases = trimmedAliases.map((a) => a.toUpperCase()).sort((a, b) => a.localeCompare(b));
    return sortedAliases[0]!;
  }

  // 5. Fallback
  return 'UNKNOWN';
}

/**
 * Generates an ecosystem-aware deterministic SHA-256 fingerprint for dependency findings:
 * sha256("dependency:" + ecosystem.trim().toLowerCase() + ":" + packageName.trim().toLowerCase() + ":" + packageVersion.trim() + ":" + canonicalVulnerabilityId.trim().toUpperCase())
 *
 * Strictly excludes file, manifestPath, scanner, severity, title, and description.
 */
export function generateDependencyFingerprint(
  ecosystem: string,
  packageName: string,
  packageVersion: string,
  canonicalVulnerabilityId: string
): string {
  const raw =
    'dependency:' +
    ecosystem.trim().toLowerCase() + ':' +
    packageName.trim().toLowerCase() + ':' +
    packageVersion.trim() + ':' +
    canonicalVulnerabilityId.trim().toUpperCase();

  return crypto.createHash('sha256').update(raw).digest('hex');
}

/**
 * Maps raw dependency severity to SafeRepo's 5-level severity model.
 * Never invents severity; missing/unknown safely defaults to 'info'.
 */
export function mapDependencySeverity(rawSeverity?: string | null): FindingSeverity {
  if (!rawSeverity || typeof rawSeverity !== 'string') {
    return 'info';
  }

  switch (rawSeverity.trim().toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
    case 'MODERATE':
      return 'medium';
    case 'LOW':
      return 'low';
    case 'INFO':
    case 'UNKNOWN':
      return 'info';
    default:
      return 'info';
  }
}

/**
 * Infers ecosystem from manifest file path.
 */
export function inferEcosystemFromPath(
  manifestPath?: string | null
): DependencyEcosystem | 'unknown' {
  if (!manifestPath || typeof manifestPath !== 'string') {
    return 'unknown';
  }

  const normalized = manifestPath.replace(/\\/g, '/').toLowerCase();
  const basename = normalized.split('/').pop() || normalized;

  if (
    basename === 'package-lock.json' ||
    basename === 'package.json' ||
    basename === 'yarn.lock' ||
    basename === 'pnpm-lock.yaml'
  ) {
    return 'npm';
  }

  if (
    basename === 'requirements.txt' ||
    basename === 'pipfile.lock' ||
    basename === 'pyproject.toml' ||
    basename === 'poetry.lock'
  ) {
    return 'pypi';
  }

  return 'unknown';
}

/**
 * Normalizes a single Trivy vulnerability finding into a NormalizedFindingInput.
 */
export function normalizeTrivyFinding(
  scanId: string,
  userId: string,
  finding: TrivyVulnerabilityFinding,
  defaultEcosystem?: DependencyEcosystem
): NormalizedFindingInput {
  const target = finding.target || 'manifest';
  const inferred = inferEcosystemFromPath(target);
  const ecosystem: string =
    inferred !== 'unknown'
      ? inferred
      : defaultEcosystem ?? 'npm';

  const canonicalId = resolveCanonicalVulnerabilityId(
    finding.vulnerabilityId,
    finding.aliases
  );
  const pkgName = finding.package.trim().toLowerCase();
  const pkgVersion = finding.packageVersion.trim();
  const fingerprint = generateDependencyFingerprint(
    ecosystem,
    pkgName,
    pkgVersion,
    canonicalId
  );

  const rawAliases = Array.isArray(finding.aliases) ? finding.aliases : [];
  const aliases = Array.from(
    new Set(
      [finding.vulnerabilityId, canonicalId, ...rawAliases]
        .filter((a): a is string => typeof a === 'string' && a.trim().length > 0)
        .map((a) => a.trim().toUpperCase())
    )
  ).sort((a, b) => a.localeCompare(b));

  const title = finding.title?.trim() || `${canonicalId} in ${pkgName}`;
  const description = finding.description?.trim() || title;

  return {
    scanId,
    userId,
    scanner: 'trivy',
    category: 'dependency',
    severity: finding.severity,
    title,
    description,
    file: target,
    line: 0,
    package: pkgName,
    packageVersion: pkgVersion,
    fixedVersion: finding.fixedVersion?.trim() || undefined,
    vulnerabilityId: canonicalId,
    remediation: finding.remediation,
    fingerprint,
    metadata: {
      scanners: ['trivy'],
      ecosystem,
      aliases,
      manifestPaths: [target],
      rawVulnerability: finding.rawVulnerability,
    },
  };
}

/**
 * Normalizes a single OSV vulnerability finding into a NormalizedFindingInput.
 */
export function normalizeOsvFinding(
  scanId: string,
  userId: string,
  finding: OsvVulnerabilityFinding
): NormalizedFindingInput {
  const target = finding.target || 'manifest';
  const inferred = inferEcosystemFromPath(target);
  const ecosystem = (
    finding.ecosystem ||
    (inferred !== 'unknown' ? inferred : 'npm')
  ).toLowerCase();

  const canonicalId = resolveCanonicalVulnerabilityId(
    finding.vulnerabilityId,
    finding.aliases
  );
  const pkgName = finding.package.trim().toLowerCase();
  const pkgVersion = finding.packageVersion.trim();
  const fingerprint = generateDependencyFingerprint(
    ecosystem,
    pkgName,
    pkgVersion,
    canonicalId
  );

  const rawAliases = Array.isArray(finding.aliases) ? finding.aliases : [];
  const aliases = Array.from(
    new Set(
      [finding.vulnerabilityId, canonicalId, ...rawAliases]
        .filter((a): a is string => typeof a === 'string' && a.trim().length > 0)
        .map((a) => a.trim().toUpperCase())
    )
  ).sort((a, b) => a.localeCompare(b));

  const title = finding.title?.trim() || `${canonicalId} in ${pkgName}`;
  const description = finding.description?.trim() || title;

  return {
    scanId,
    userId,
    scanner: 'osv',
    category: 'dependency',
    severity: finding.severity,
    title,
    description,
    file: target,
    line: 0,
    package: pkgName,
    packageVersion: pkgVersion,
    fixedVersion: finding.fixedVersion?.trim() || undefined,
    vulnerabilityId: canonicalId,
    remediation: finding.remediation,
    fingerprint,
    metadata: {
      scanners: ['osv'],
      ecosystem,
      aliases,
      manifestPaths: target !== 'manifest' ? [target] : [],
      rawVulnerability: finding.rawVulnerability,
    },
  };
}

/**
 * Merges two dependency findings with identical fingerprints from different or same scanners.
 * Pure function: returns a new cloned object without mutating inputs.
 */
export function mergeDependencyFindings(
  existing: NormalizedFindingInput,
  incoming: NormalizedFindingInput
): NormalizedFindingInput {
  // 1. Unique, deterministic scanners list
  const existingScanners = Array.isArray(existing.metadata?.scanners)
    ? (existing.metadata?.scanners as string[])
    : [existing.scanner];
  const incomingScanners = Array.isArray(incoming.metadata?.scanners)
    ? (incoming.metadata?.scanners as string[])
    : [incoming.scanner];

  const mergedScanners = Array.from(
    new Set([...existingScanners, ...incomingScanners])
  ).sort((a, b) => a.localeCompare(b));

  // 2. Highest severity selection (critical > high > medium > low > info)
  const existingRank = SEVERITY_RANK[existing.severity] ?? 1;
  const incomingRank = SEVERITY_RANK[incoming.severity] ?? 1;
  const highestSeverity = incomingRank > existingRank ? incoming.severity : existing.severity;

  // 3. Aliases union (unique, deterministically sorted)
  const existingAliases = Array.isArray(existing.metadata?.aliases)
    ? (existing.metadata?.aliases as string[])
    : [];
  const incomingAliases = Array.isArray(incoming.metadata?.aliases)
    ? (incoming.metadata?.aliases as string[])
    : [];
  const mergedAliases = Array.from(
    new Set([
      existing.vulnerabilityId,
      incoming.vulnerabilityId,
      ...existingAliases,
      ...incomingAliases,
    ].filter(Boolean))
  ).sort((a, b) => a.localeCompare(b));

  // 4. Manifest paths union
  const existingPaths = Array.isArray(existing.metadata?.manifestPaths)
    ? (existing.metadata?.manifestPaths as string[])
    : existing.file && existing.file !== 'manifest' ? [existing.file] : [];
  const incomingPaths = Array.isArray(incoming.metadata?.manifestPaths)
    ? (incoming.metadata?.manifestPaths as string[])
    : incoming.file && incoming.file !== 'manifest' ? [incoming.file] : [];
  const mergedPaths = Array.from(
    new Set([...existingPaths, ...incomingPaths].filter(Boolean))
  ).sort((a, b) => a.localeCompare(b));

  // 5. Fixed version preservation
  let fixedVersion = existing.fixedVersion;
  if (!fixedVersion && incoming.fixedVersion) {
    fixedVersion = incoming.fixedVersion;
  } else if (fixedVersion && incoming.fixedVersion && fixedVersion !== incoming.fixedVersion) {
    // Deterministic safe rule if both exist and differ: higher sorted version
    fixedVersion = [fixedVersion, incoming.fixedVersion].sort((a, b) => a.localeCompare(b)).reverse()[0];
  }

  // 6. Remediation preservation (prefer actionable upgrade instructions over generic/empty)
  let remediation = existing.remediation;
  const incomingIsActionable =
    incoming.remediation &&
    incoming.remediation.toLowerCase().startsWith('upgrade') &&
    (!existing.remediation || existing.remediation.toLowerCase().startsWith('no fixed'));

  if (!remediation || incomingIsActionable) {
    remediation = incoming.remediation || remediation;
  }

  // 7. Title & Description preservation (prefer longer, non-generic descriptions)
  let title = existing.title;
  const incomingTitleIsBetter =
    incoming.title &&
    incoming.title.length > (title?.length ?? 0) &&
    !incoming.title.startsWith(incoming.vulnerabilityId);

  if (!title || incomingTitleIsBetter) {
    title = incoming.title;
  }

  let description = existing.description;
  if (
    !description ||
    (incoming.description && incoming.description.length > description.length)
  ) {
    description = incoming.description;
  }

  // 8. File preservation
  const file =
    existing.file && existing.file !== 'manifest'
      ? existing.file
      : (incoming.file || existing.file);

  return {
    ...existing,
    severity: highestSeverity,
    title,
    description,
    file,
    fixedVersion,
    remediation,
    metadata: {
      ...existing.metadata,
      ...incoming.metadata,
      scanners: mergedScanners,
      aliases: mergedAliases,
      manifestPaths: mergedPaths,
    },
  };
}

/**
 * Deduplicates dependency findings by fingerprint using an in-memory Map.
 */
export function deduplicateDependencyFindings(
  findings: NormalizedFindingInput[]
): NormalizedFindingInput[] {
  const map = new Map<string, NormalizedFindingInput>();

  for (const finding of findings) {
    const existing = map.get(finding.fingerprint);
    if (!existing) {
      // Clone to ensure immutability
      map.set(finding.fingerprint, {
        ...finding,
        metadata: {
          ...finding.metadata,
          scanners: Array.isArray(finding.metadata?.scanners)
            ? [...(finding.metadata?.scanners as string[])]
            : [finding.scanner],
          aliases: Array.isArray(finding.metadata?.aliases)
            ? [...(finding.metadata?.aliases as string[])]
            : [],
          manifestPaths: Array.isArray(finding.metadata?.manifestPaths)
            ? [...(finding.metadata?.manifestPaths as string[])]
            : finding.file && finding.file !== 'manifest' ? [finding.file] : [],
        },
      });
    } else {
      map.set(finding.fingerprint, mergeDependencyFindings(existing, finding));
    }
  }

  return Array.from(map.values());
}

/**
 * Safely parses Trivy findings input from array or JSON string.
 */
function parseTrivyInput(raw: TrivyVulnerabilityFinding[] | string): TrivyVulnerabilityFinding[] {
  if (Array.isArray(raw)) {
    return raw;
  }
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed as TrivyVulnerabilityFinding[];
    }
    return parseTrivyJsonOutput(raw);
  } catch (err) {
    throw new Error(
      'Failed to parse Trivy output: ' + (err instanceof Error ? err.message : String(err))
    );
  }
}

/**
 * Safely parses OSV findings input from array or JSON string.
 */
function parseOsvInput(raw: OsvVulnerabilityFinding[] | string): OsvVulnerabilityFinding[] {
  if (Array.isArray(raw)) {
    return raw;
  }
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed as OsvVulnerabilityFinding[];
    }
    throw new Error('OSV output must be a JSON array of findings');
  } catch (err) {
    throw new Error(
      'Failed to parse OSV JSON output: ' + (err instanceof Error ? err.message : String(err))
    );
  }
}

/**
 * Normalizes raw Trivy output into unified finding schema with cross-finding deduplication.
 */
export function normalizeTrivyOutput(
  scanId: string,
  userId: string,
  rawOutput: TrivyVulnerabilityFinding[] | string,
  defaultEcosystem?: DependencyEcosystem,
  maxFindings = 5000
): NormalizationResult {
  const items = parseTrivyInput(rawOutput);

  const normalizedList: NormalizedFindingInput[] = [];
  for (const item of items) {
    if (normalizedList.length >= maxFindings) break;
    normalizedList.push(normalizeTrivyFinding(scanId, userId, item, defaultEcosystem));
  }

  const deduped = deduplicateDependencyFindings(normalizedList);

  const summary: ScanSummary = {
    total: deduped.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const f of deduped) {
    summary[f.severity]++;
  }

  return {
    findings: deduped,
    summary,
    rawMatchesCount: items.length,
    dedupedCount: deduped.length,
  };
}

/**
 * Normalizes raw OSV output into unified finding schema with cross-finding deduplication.
 */
export function normalizeOsvOutput(
  scanId: string,
  userId: string,
  rawOutput: OsvVulnerabilityFinding[] | string,
  maxFindings = 5000
): NormalizationResult {
  const items = parseOsvInput(rawOutput);

  const normalizedList: NormalizedFindingInput[] = [];
  for (const item of items) {
    if (normalizedList.length >= maxFindings) break;
    normalizedList.push(normalizeOsvFinding(scanId, userId, item));
  }

  const deduped = deduplicateDependencyFindings(normalizedList);

  const summary: ScanSummary = {
    total: deduped.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const f of deduped) {
    summary[f.severity]++;
  }

  return {
    findings: deduped,
    summary,
    rawMatchesCount: items.length,
    dedupedCount: deduped.length,
  };
}

/**
 * Normalizes and deduplicates dependency findings across both Trivy and OSV scanners.
 */
export function normalizeDependencyFindings(
  scanId: string,
  userId: string,
  options: NormalizeDependencyFindingsOptions
): NormalizationResult {
  const {
    trivyFindings,
    osvFindings,
    defaultEcosystem,
    maxFindings = 5000,
  } = options;

  const allNormalized: NormalizedFindingInput[] = [];
  let rawCount = 0;

  if (trivyFindings) {
    const tItems = parseTrivyInput(trivyFindings);
    rawCount += tItems.length;
    for (const item of tItems) {
      if (allNormalized.length >= maxFindings) break;
      allNormalized.push(normalizeTrivyFinding(scanId, userId, item, defaultEcosystem));
    }
  }

  if (osvFindings && allNormalized.length < maxFindings) {
    const oItems = parseOsvInput(osvFindings);
    rawCount += oItems.length;
    for (const item of oItems) {
      if (allNormalized.length >= maxFindings) break;
      allNormalized.push(normalizeOsvFinding(scanId, userId, item));
    }
  }

  const deduped = deduplicateDependencyFindings(allNormalized);

  const summary: ScanSummary = {
    total: deduped.length,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  for (const f of deduped) {
    summary[f.severity]++;
  }

  return {
    findings: deduped,
    summary,
    rawMatchesCount: rawCount,
    dedupedCount: deduped.length,
  };
}
