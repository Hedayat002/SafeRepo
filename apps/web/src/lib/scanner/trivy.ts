import fs from 'fs/promises';
import path from 'path';
import { runDockerScanner, ScannerTimeoutError, OutputSizeExceededError } from './runner';
import type { FindingSeverity, ScannerResult } from '@/types';
import { logger } from '@/lib/logger';
import { env } from '@/lib/env';

/**
 * Normalized vulnerability finding extracted from Trivy output.
 */
export interface TrivyVulnerabilityFinding {
  vulnerabilityId: string;
  canonicalId: string;
  package: string;
  packageVersion: string;
  fixedVersion?: string;
  severity: FindingSeverity;
  title: string;
  description: string;
  target: string;
  remediation?: string;
  aliases: string[];
  rawVulnerability: unknown;
}

export type TrivyScannerResult = ScannerResult<TrivyVulnerabilityFinding>;

export interface ExecuteTrivyScanOptions {
  scanId: string;
  userId: string;
  workspacePath: string;
  trivyDbPath?: string;
  image?: string;
  timeoutMs?: number;
  memoryLimit?: string;
}

/**
 * Maps Trivy raw severity string to SafeRepo's 5-level severity model.
 */
export function mapTrivySeverity(rawSeverity?: string): FindingSeverity {
  if (!rawSeverity) return 'medium';

  switch (rawSeverity.trim().toUpperCase()) {
    case 'CRITICAL':
      return 'critical';
    case 'HIGH':
      return 'high';
    case 'MEDIUM':
      return 'medium';
    case 'LOW':
      return 'low';
    case 'UNKNOWN':
    case 'INFO':
      return 'info';
    default:
      return 'medium';
  }
}

/**
 * Resolves a canonical vulnerability ID, prioritizing standard CVE IDs over vendor/ecosystem IDs.
 */
export function resolveCanonicalVulnerabilityId(
  vulnerabilityId: string,
  aliases: string[] = []
): string {
  const cveRegex = /^CVE-\d{4}-\d+$/i;
  const allIds = [vulnerabilityId, ...aliases].map((id) => id.trim());

  const cveMatches = allIds.filter((id) => cveRegex.test(id));
  if (cveMatches.length > 0) {
    // Deterministic selection: pick the first CVE, normalized to uppercase
    return cveMatches[0]!.toUpperCase();
  }

  return vulnerabilityId.trim().toUpperCase();
}

/**
 * Validates and normalizes Trivy target manifest paths.
 *
 * Security Invariants:
 * - Paths MUST resolve strictly inside the /src container mount.
 * - Traversal attempts (e.g. "../../etc/passwd", "/src/../../etc/passwd") MUST be REJECTED (returns null).
 * - Absolute paths outside /src (e.g. "/etc/shadow", "C:\Windows\...") MUST be REJECTED (returns null).
 * - Traversal components are NEVER stripped into synthetic basenames.
 *
 * Returns normalized workspace-relative path (e.g. "package-lock.json") or null if invalid/rejected.
 */
export function validateAndNormalizeTrivyTargetPath(rawTarget?: string): string | null {
  if (!rawTarget || typeof rawTarget !== 'string') return null;

  const trimmed = rawTarget.trim();
  if (!trimmed) return null;

  // Reject Windows drive paths (e.g. C:\Windows\...)
  if (/^[a-zA-Z]:[/\\]/.test(trimmed)) {
    return null;
  }

  // Normalize slashes to POSIX
  const posixPath = trimmed.replace(/\\/g, '/');

  // Must resolve strictly within /src container mount
  const base = '/src';
  let resolved: string;
  if (posixPath.startsWith('/')) {
    resolved = path.posix.normalize(posixPath);
  } else {
    resolved = path.posix.normalize(path.posix.join(base, posixPath));
  }

  // Enforce boundary: resolved path must be a child of /src (start with "/src/")
  if (!resolved.startsWith(base + '/')) {
    // Traversal outside /src or root /src itself
    return null;
  }

  // Extract relative path inside /src
  const relative = resolved.substring(base.length + 1);

  // Reject empty or invalid relative remnants
  if (!relative || relative.startsWith('..') || path.posix.isAbsolute(relative)) {
    return null;
  }

  return relative;
}

/**
 * Normalizes Trivy target manifest paths.
 * Returns normalized workspace-relative path or null if rejected.
 */
export function normalizeTrivyTargetPath(rawTarget?: string): string | null {
  return validateAndNormalizeTrivyTargetPath(rawTarget);
}

/**
 * Validates the existence, structure, and readability of the Trivy offline vulnerability database.
 * Requires BOTH non-empty `trivy.db` binary and valid `metadata.json` schema.
 * Does not throw exceptions; returns a typed operational validation result.
 */
export async function validateTrivyDb(
  dbPath?: string
): Promise<{ valid: boolean; reason?: string }> {
  if (!dbPath || !dbPath.trim()) {
    return {
      valid: false,
      reason: 'Trivy offline vulnerability database not found at TRIVY_DB_PATH',
    };
  }

  const resolved = path.resolve(dbPath.trim());

  try {
    const stats = await fs.stat(resolved);
    if (!stats.isDirectory()) {
      return {
        valid: false,
        reason: 'Trivy offline vulnerability database not found at TRIVY_DB_PATH',
      };
    }

    // Check read permission on the directory
    await fs.access(resolved, fs.constants.R_OK);

    // 1. Validate trivy.db (must exist, be a file, be readable, and non-empty)
    const dbFilePath = path.join(resolved, 'trivy.db');
    try {
      const dbStat = await fs.stat(dbFilePath);
      if (!dbStat.isFile() || dbStat.size === 0) {
        return {
          valid: false,
          reason: 'Trivy database file (trivy.db) is missing or empty',
        };
      }
      await fs.access(dbFilePath, fs.constants.R_OK);
    } catch {
      return {
        valid: false,
        reason: 'Trivy database file (trivy.db) is missing or empty',
      };
    }

    // 2. Validate metadata.json (must exist, be a file, be readable, and contain valid JSON with positive Version)
    const metadataFilePath = path.join(resolved, 'metadata.json');
    try {
      const metaStat = await fs.stat(metadataFilePath);
      if (!metaStat.isFile() || metaStat.size === 0) {
        return {
          valid: false,
          reason: 'Trivy database metadata (metadata.json) is missing or invalid',
        };
      }
      await fs.access(metadataFilePath, fs.constants.R_OK);

      const metaContent = await fs.readFile(metadataFilePath, 'utf-8');
      const parsedMeta = JSON.parse(metaContent) as { Version?: unknown };
      if (typeof parsedMeta.Version !== 'number' || parsedMeta.Version < 1) {
        return {
          valid: false,
          reason: 'Trivy database metadata (metadata.json) is missing or invalid',
        };
      }
    } catch {
      return {
        valid: false,
        reason: 'Trivy database metadata (metadata.json) is missing or invalid',
      };
    }

    return { valid: true };
  } catch {
    return {
      valid: false,
      reason: 'Trivy offline vulnerability database not found at TRIVY_DB_PATH',
    };
  }
}

interface RawTrivyVulnerability {
  VulnerabilityID?: string;
  PkgName?: string;
  InstalledVersion?: string;
  FixedVersion?: string;
  Severity?: string;
  Title?: string;
  Description?: string;
  Aliases?: string[];
  [key: string]: unknown;
}

interface RawTrivyResult {
  Target?: string;
  Class?: string;
  Type?: string;
  Vulnerabilities?: RawTrivyVulnerability[];
  [key: string]: unknown;
}

interface RawTrivyOutput {
  Results?: RawTrivyResult[];
  [key: string]: unknown;
}

/**
 * Parses and normalizes raw Trivy JSON output.
 * Throws controlled Error if JSON is malformed.
 */
export function parseTrivyJsonOutput(
  stdout: string,
  workspacePath?: string
): TrivyVulnerabilityFinding[] {
  if (workspacePath) {
    logger.debug({ workspacePath }, 'Parsing Trivy output for workspace');
  }
  let parsed: RawTrivyOutput;
  try {
    parsed = JSON.parse(stdout) as RawTrivyOutput;
  } catch {
    throw new Error('Failed to parse Trivy output: Invalid JSON');
  }

  if (!parsed || !Array.isArray(parsed.Results)) {
    return [];
  }

  const findings: TrivyVulnerabilityFinding[] = [];

  for (const result of parsed.Results) {
    if (!result || !Array.isArray(result.Vulnerabilities)) {
      continue;
    }

    const target = normalizeTrivyTargetPath(result.Target);
    if (!target) {
      logger.warn(
        { rawTarget: result.Target },
        'Rejected Trivy result with target path resolving outside /src workspace mount'
      );
      continue;
    }

    for (const vuln of result.Vulnerabilities) {
      if (!vuln || !vuln.VulnerabilityID || !vuln.PkgName) {
        continue;
      }

      const vulnerabilityId = vuln.VulnerabilityID.trim();
      const rawAliases = Array.isArray(vuln.Aliases) ? vuln.Aliases.filter((a): a is string => typeof a === 'string') : [];
      const canonicalId = resolveCanonicalVulnerabilityId(vulnerabilityId, rawAliases);

      const pkgName = vuln.PkgName.trim().toLowerCase();
      const installedVersion = (vuln.InstalledVersion ?? 'unknown').trim();
      const fixedVersion = vuln.FixedVersion ? vuln.FixedVersion.trim() : undefined;

      const severity = mapTrivySeverity(vuln.Severity);

      const title = vuln.Title
        ? vuln.Title.trim().substring(0, 120)
        : `${canonicalId} in ${pkgName}`;

      const description = vuln.Description ? vuln.Description.trim() : title;

      const remediation = fixedVersion
        ? `Upgrade ${pkgName} to ${fixedVersion}`
        : `No fixed version available for ${canonicalId}`;

      // Build deduplicated aliases list containing all known IDs
      const aliases = Array.from(new Set([vulnerabilityId, ...rawAliases]));

      findings.push({
        vulnerabilityId,
        canonicalId,
        package: pkgName,
        packageVersion: installedVersion,
        fixedVersion,
        severity,
        title,
        description,
        target,
        remediation,
        aliases,
        rawVulnerability: vuln,
      });
    }
  }

  return findings;
}

/**
 * Executes Trivy SCA filesystem scan inside Stage 1 Docker isolation.
 *
 * Enforces:
 * - Offline DB availability validation before container spawn
 * - Hardened non-root Stage 1 isolation (--network=none, --read-only, --user 1000:1000)
 * - Safe non-root cache (/home/scanner/.cache/trivy)
 * - Resource limits and timeouts
 * - Explicit discriminated union ScannerResult
 */
export async function executeTrivyScan(
  options: ExecuteTrivyScanOptions
): Promise<TrivyScannerResult> {
  const {
    scanId,
    userId,
    workspacePath,
    trivyDbPath = env.TRIVY_DB_PATH,
    image = env.TRIVY_IMAGE,
    timeoutMs = env.TRIVY_TIMEOUT_MS,
    memoryLimit = env.TRIVY_MEMORY_LIMIT,
  } = options;

  const startTime = Date.now();

  logger.info({ scanId, userId, workspacePath, trivyDbPath }, 'Evaluating Trivy offline DB availability');

  // Step 1: Evaluate Trivy DB availability
  const dbValidation = await validateTrivyDb(trivyDbPath);
  if (!dbValidation.valid) {
    logger.warn(
      { scanId, trivyDbPath, reason: dbValidation.reason },
      'Trivy offline database unavailable; returning typed unavailable result'
    );
    return {
      status: 'unavailable',
      scanner: 'trivy',
      reason: dbValidation.reason ?? 'Trivy offline vulnerability database not found at TRIVY_DB_PATH',
    };
  }

  // Step 2: Build Stage 1 Docker arguments and spawn container
  logger.info({ scanId, image, timeoutMs }, 'Executing Trivy inside Stage 1 Docker container');

  const resolvedDbPath = path.resolve(trivyDbPath!.trim());

  try {
    const runnerResult = await runDockerScanner({
      scanId,
      scannerName: 'trivy',
      workspacePath,
      image,
      commandArgs: [
        'fs',
        '--format', 'json',
        '--offline-scan',
        '--skip-db-update',
        '--cache-dir', '/home/scanner/.cache/trivy',
        '--scanners', 'vuln',
        '/src',
      ],
      timeoutMs,
      memoryLimit,
      homeTmpfs: '/home/scanner:rw,noexec,nosuid,size=128m,uid=1000,gid=1000',
      extraEnv: {
        HOME: '/home/scanner',
        TRIVY_CACHE_DIR: '/home/scanner/.cache/trivy',
      },
      extraMounts: [
        {
          source: resolvedDbPath,
          target: '/home/scanner/.cache/trivy/db',
          readonly: true,
        },
      ],
    });

    if (runnerResult.exitCode !== 0) {
      const durationMs = Date.now() - startTime;
      logger.warn(
        { scanId, exitCode: runnerResult.exitCode, stderr: runnerResult.stderr },
        'Trivy scanner container exited with non-zero code'
      );
      return {
        status: 'failed',
        scanner: 'trivy',
        error: `Trivy exited with non-zero exit code ${runnerResult.exitCode}: ${runnerResult.stderr || 'No error output'}`,
        durationMs,
      };
    }

    const findings = parseTrivyJsonOutput(runnerResult.stdout, workspacePath);
    const durationMs = runnerResult.durationMs ?? (Date.now() - startTime);

    logger.info(
      { scanId, matchesCount: findings.length, durationMs },
      'Trivy scan completed successfully'
    );

    return {
      status: 'success',
      scanner: 'trivy',
      findings,
      durationMs,
      rawMatchesCount: findings.length,
    };
  } catch (err: unknown) {
    const durationMs = Date.now() - startTime;

    if (err instanceof ScannerTimeoutError) {
      logger.error({ scanId, timeoutMs }, 'Trivy scanner container timed out');
      return {
        status: 'failed',
        scanner: 'trivy',
        error: `Trivy scan timed out after ${timeoutMs}ms`,
        durationMs,
      };
    }

    if (err instanceof OutputSizeExceededError) {
      logger.error({ scanId }, 'Trivy scanner stdout exceeded buffer limit');
      return {
        status: 'failed',
        scanner: 'trivy',
        error: err.message,
        durationMs,
      };
    }

    const errorMessage = err instanceof Error ? err.message : String(err);
    logger.error({ scanId, err: errorMessage }, 'Trivy scan encountered execution failure');

    return {
      status: 'failed',
      scanner: 'trivy',
      error: errorMessage,
      durationMs,
    };
  }
}
