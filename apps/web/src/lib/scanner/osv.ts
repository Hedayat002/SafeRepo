import type {
  DependencyCoordinate,
  FindingSeverity,
  ScannerSuccessResult,
  ScannerFailedResult,
} from '@/types';
import { logger } from '@/lib/logger';
import { env } from '@/lib/env';

export interface OsvVulnerabilityFinding {
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
  ecosystem: string;
  rawVulnerability: unknown;
}

export type OsvScannerResult =
  | ScannerSuccessResult<OsvVulnerabilityFinding>
  | ScannerFailedResult;

export interface ExecuteOsvScanOptions {
  scanId: string;
  userId: string;
  coordinates: DependencyCoordinate[];
  apiUrl?: string;
  timeoutMs?: number;
  maxRetries?: number;
  initialBackoffMs?: number;
}

export interface OsvQueryItem {
  package: {
    name: string;
    ecosystem: 'npm' | 'PyPI';
  };
  version: string;
}

export interface OsvBatchRequestBody {
  queries: OsvQueryItem[];
}

export interface RawOsvAffected {
  package?: {
    name?: string;
    ecosystem?: string;
  };
  ranges?: Array<{
    type?: string;
    events?: Array<{
      introduced?: string;
      fixed?: string;
      [key: string]: unknown;
    }>;
  }>;
  versions?: string[];
  [key: string]: unknown;
}

export interface RawOsvVulnerability {
  id?: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  database_specific?: {
    severity?: string;
    [key: string]: unknown;
  };
  severity?: Array<{
    type?: string;
    score?: string;
  }>;
  affected?: RawOsvAffected[];
  [key: string]: unknown;
}

export interface RawOsvBatchResultItem {
  vulns?: RawOsvVulnerability[];
  [key: string]: unknown;
}

export interface RawOsvBatchResponse {
  results?: RawOsvBatchResultItem[];
  [key: string]: unknown;
}

/** Maximum coordinates allowed per OSV query batch */
export const OSV_MAX_BATCH_SIZE = 100;

/**
 * Validates whether a version string is an exact resolved version.
 * Rejects ranges, wildcards, or unresolved specifiers.
 */
export function isExactResolvedVersion(version: string): boolean {
  if (!version || typeof version !== 'string') return false;
  const trimmed = version.trim();

  // Reject range operators and wildcards
  if (/[\^~><*|]/.test(trimmed)) return false;

  // Reject keywords
  if (['latest', 'next', 'beta', 'alpha', 'rc', 'dev', 'unknown'].includes(trimmed.toLowerCase())) {
    return false;
  }

  // Reject git or file URLs
  if (trimmed.startsWith('git') || trimmed.startsWith('file:') || trimmed.startsWith('http')) {
    return false;
  }

  // Must match standard semver or numeric version pattern
  return /^[a-zA-Z0-9_\-\.\+]+$/.test(trimmed);
}

/**
 * Normalizes an ecosystem name to OSV's expected casing:
 * 'npm' -> 'npm'
 * 'pypi' -> 'PyPI'
 */
export function mapEcosystemToOsv(ecosystem: string): 'npm' | 'PyPI' {
  if (ecosystem.toLowerCase() === 'pypi') {
    return 'PyPI';
  }
  return 'npm';
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
    return cveMatches[0]!.toUpperCase();
  }

  return vulnerabilityId.trim().toUpperCase();
}

/**
 * Maps OSV severity data (database_specific or CVSS) to SafeRepo's 5-level severity model.
 */
export function mapOsvSeverity(vuln: RawOsvVulnerability): FindingSeverity {
  // 1. Check database_specific.severity
  const dbSeverity = vuln.database_specific?.severity;
  if (typeof dbSeverity === 'string') {
    switch (dbSeverity.trim().toUpperCase()) {
      case 'CRITICAL':
        return 'critical';
      case 'HIGH':
        return 'high';
      case 'MODERATE':
      case 'MEDIUM':
        return 'medium';
      case 'LOW':
        return 'low';
      case 'UNKNOWN':
      case 'INFO':
        return 'info';
    }
  }

  // 2. Check CVSS score or vector if available
  if (Array.isArray(vuln.severity)) {
    for (const s of vuln.severity) {
      if (s?.score && typeof s.score === 'string') {
        const str = s.score.trim();

        // Direct numeric score (e.g. "9.8", "7.5", "5.0")
        const directNum = parseFloat(str);
        if (!isNaN(directNum) && !str.startsWith('CVSS:')) {
          if (directNum >= 9.0) return 'critical';
          if (directNum >= 7.0) return 'high';
          if (directNum >= 4.0) return 'medium';
          if (directNum > 0.0) return 'low';
          return 'info';
        }

        // CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
        if (str.startsWith('CVSS:')) {
          if ((str.includes('/C:H/I:H') || str.includes('C:H/I:H/A:H')) && str.includes('/AV:N')) {
            return 'critical';
          }
          if (str.includes('/C:H') || str.includes('/I:H') || str.includes('/A:H')) {
            return 'high';
          }
          if (str.includes('/C:L/I:L') || (str.includes('/C:L') && str.includes('/I:L'))) {
            return 'medium';
          }
          if (str.includes('/C:L') || str.includes('/I:L') || str.includes('/A:L')) {
            return 'low';
          }
        }
      }
    }
  }

  return 'medium';
}

/**
 * Extracts the earliest or matching fixed version from an OSV affected entry.
 */
export function extractFixedVersion(
  vuln: RawOsvVulnerability,
  packageName: string
): string | undefined {
  if (!Array.isArray(vuln.affected)) return undefined;

  const normalizedPkg = packageName.trim().toLowerCase();

  for (const affected of vuln.affected) {
    const affectedName = affected?.package?.name?.trim().toLowerCase();
    if (affectedName && affectedName !== normalizedPkg) {
      continue;
    }

    if (Array.isArray(affected.ranges)) {
      for (const range of affected.ranges) {
        if (Array.isArray(range.events)) {
          for (const event of range.events) {
            if (typeof event.fixed === 'string' && event.fixed.trim()) {
              return event.fixed.trim();
            }
          }
        }
      }
    }
  }

  return undefined;
}

/**
 * Chunks dependency coordinates into batches of up to OSV_MAX_BATCH_SIZE (100).
 * Strictly filters out invalid or unresolved versions.
 */
export function chunkCoordinates(
  coordinates: DependencyCoordinate[],
  maxBatchSize = OSV_MAX_BATCH_SIZE
): DependencyCoordinate[][] {
  const validCoordinates = coordinates.filter((coord) => {
    if (!coord.name || !coord.version) return false;
    return isExactResolvedVersion(coord.version);
  });

  const batches: DependencyCoordinate[][] = [];
  for (let i = 0; i < validCoordinates.length; i += maxBatchSize) {
    batches.push(validCoordinates.slice(i, i + maxBatchSize));
  }

  return batches;
}

/**
 * Executes a single POST request to the OSV querybatch endpoint with retries on transient errors.
 */
async function postOsvBatchWithRetry(
  apiUrl: string,
  body: OsvBatchRequestBody,
  timeoutMs: number,
  maxRetries = 3,
  initialBackoffMs = 200
): Promise<RawOsvBatchResponse> {
  const jsonPayload = JSON.stringify(body);

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
      const response = await fetch(apiUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Accept: 'application/json',
        },
        body: jsonPayload,
        signal: controller.signal,
        redirect: 'error',
      });

      clearTimeout(timer);

      // Transient rate-limiting or server errors: retry with backoff
      if (response.status === 429 || response.status === 503) {
        if (attempt < maxRetries) {
          const backoff = initialBackoffMs * Math.pow(2, attempt);
          logger.warn(
            { status: response.status, attempt, backoff },
            'OSV API returned transient error; retrying after backoff'
          );
          await new Promise((resolve) => setTimeout(resolve, backoff));
          continue;
        }

        throw new Error(`OSV API transient error HTTP ${response.status} exceeded retry limit`);
      }

      // Non-transient errors (e.g. 400 Bad Request, 404, 500)
      if (!response.ok) {
        throw new Error(`OSV API request failed with HTTP ${response.status}: ${response.statusText}`);
      }

      const parsed = (await response.json()) as RawOsvBatchResponse;
      if (!parsed || typeof parsed !== 'object' || !Array.isArray(parsed.results)) {
        throw new Error('Malformed OSV API response: missing results array');
      }

      return parsed;
    } catch (err: unknown) {
      clearTimeout(timer);

      if (err instanceof Error && err.name === 'AbortError') {
        throw new Error(`OSV API request timed out after ${timeoutMs}ms`);
      }

      // If it's already an OSV API HTTP error or malformed response error, do not retry
      const errMsg = err instanceof Error ? err.message : String(err);
      if (errMsg.includes('OSV API request failed with HTTP') || errMsg.includes('Malformed OSV API response')) {
        throw err;
      }

      // Transient network failure (e.g. fetch failed / ECONNRESET)
      if (attempt < maxRetries) {
        const backoff = initialBackoffMs * Math.pow(2, attempt);
        logger.warn(
          { err: errMsg, attempt, backoff },
          'OSV API network error encountered; retrying after backoff'
        );
        await new Promise((resolve) => setTimeout(resolve, backoff));
        continue;
      }

      throw err;
    }
  }

  throw new Error('OSV API request exceeded maximum retry attempts');
}

/**
 * Executes a host-side OSV static-coordinate vulnerability scan.
 *
 * Privacy & Security Invariants:
 * - Only statically extracted dependency coordinates (name, version, ecosystem) are sent.
 * - Zero repository source code, manifest contents, tokens, or files are transmitted.
 * - Never executes package managers (npm, pip) or lifecycle scripts.
 * - Enforces batch size limits (max 100 queries/request).
 * - Enforces request timeout (30s) and bounded retries.
 */
export async function executeOsvScan(
  options: ExecuteOsvScanOptions
): Promise<OsvScannerResult> {
  const {
    scanId,
    userId,
    coordinates,
    apiUrl = env.OSV_API_URL,
    timeoutMs = env.OSV_TIMEOUT_MS,
    maxRetries = 3,
    initialBackoffMs = 200,
  } = options;

  const startTime = Date.now();

  logger.info(
    { scanId, userId, coordinatesCount: coordinates.length },
    'Starting OSV host-side static coordinate scan'
  );

  // If no coordinates exist, return cleanly without network calls
  if (coordinates.length === 0) {
    logger.info({ scanId }, 'No dependency coordinates provided; skipping OSV queries');
    return {
      status: 'success',
      scanner: 'osv',
      findings: [],
      durationMs: 0,
      rawMatchesCount: 0,
    };
  }

  const batches = chunkCoordinates(coordinates, OSV_MAX_BATCH_SIZE);
  if (batches.length === 0) {
    logger.info({ scanId }, 'Zero valid exact dependency coordinates found; skipping OSV queries');
    return {
      status: 'success',
      scanner: 'osv',
      findings: [],
      durationMs: 0,
      rawMatchesCount: 0,
    };
  }

  const findings: OsvVulnerabilityFinding[] = [];

  try {
    for (let batchIndex = 0; batchIndex < batches.length; batchIndex++) {
      const batch = batches[batchIndex]!;

      // Construct privacy-preserving request body: ONLY package and version
      const requestBody: OsvBatchRequestBody = {
        queries: batch.map((coord) => ({
          package: {
            name: coord.name,
            ecosystem: mapEcosystemToOsv(coord.ecosystem),
          },
          version: coord.version,
        })),
      };

      const response = await postOsvBatchWithRetry(
        apiUrl,
        requestBody,
        timeoutMs,
        maxRetries,
        initialBackoffMs
      );

      const results = response.results!;

      // Correlate results with input coordinates in 1-to-1 order
      for (let i = 0; i < batch.length; i++) {
        const coord = batch[i]!;
        const resultItem = results[i];

        if (!resultItem || !Array.isArray(resultItem.vulns)) {
          continue;
        }

        for (const vuln of resultItem.vulns) {
          if (!vuln || !vuln.id) continue;

          const vulnerabilityId = vuln.id.trim();
          const rawAliases = Array.isArray(vuln.aliases)
            ? vuln.aliases.filter((a): a is string => typeof a === 'string')
            : [];

          const canonicalId = resolveCanonicalVulnerabilityId(vulnerabilityId, rawAliases);
          const severity = mapOsvSeverity(vuln);
          const fixedVersion = extractFixedVersion(vuln, coord.name);

          const title = vuln.summary
            ? vuln.summary.trim().substring(0, 120)
            : `${canonicalId} in ${coord.name}`;

          const description = vuln.details
            ? vuln.details.trim()
            : (vuln.summary?.trim() || title);

          const remediation = fixedVersion
            ? `Upgrade ${coord.name} to ${fixedVersion}`
            : `No fixed version available for ${canonicalId}`;

          const aliases = Array.from(new Set([vulnerabilityId, ...rawAliases]));

          findings.push({
            vulnerabilityId,
            canonicalId,
            package: coord.name,
            packageVersion: coord.version,
            fixedVersion,
            severity,
            title,
            description,
            target: coord.manifestPath,
            remediation,
            aliases,
            ecosystem: coord.ecosystem,
            rawVulnerability: vuln,
          });
        }
      }
    }

    const durationMs = Date.now() - startTime;
    logger.info(
      { scanId, matchesCount: findings.length, durationMs },
      'OSV static coordinate scan completed successfully'
    );

    return {
      status: 'success',
      scanner: 'osv',
      findings,
      durationMs,
      rawMatchesCount: findings.length,
    };
  } catch (err: unknown) {
    const durationMs = Date.now() - startTime;
    const errorMessage = err instanceof Error ? err.message : String(err);

    logger.error({ scanId, err: errorMessage }, 'OSV static coordinate scan failed');

    return {
      status: 'failed',
      scanner: 'osv',
      error: errorMessage,
      durationMs,
    };
  }
}
