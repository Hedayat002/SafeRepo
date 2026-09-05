import { runDockerScanner, ScannerTimeoutError, OutputSizeExceededError } from './runner';
import type { GitleaksRawFinding, ScannerResult } from '@/types';
import type { NormalizedFindingInput } from './normalizer';
import { normalizeGitleaksOutput } from './normalizer';
import { logger } from '@/lib/logger';
import { env } from '@/lib/env';

export interface ExecuteGitleaksScanOptions {
  scanId: string;
  userId: string;
  workspacePath: string;
  image?: string;
  timeoutMs?: number;
  memoryLimit?: string;
}

export type GitleaksScannerResult = ScannerResult<NormalizedFindingInput>;

/**
 * Builds deterministic command arguments for Gitleaks inside the container.
 * Enforces native process-boundary redaction and quiet execution flags.
 */
export function buildGitleaksCommandArgs(): string[] {
  return [
    'dir',
    '/src',
    '--report-format',
    'json',
    '--report-path',
    '-',
    '--redact',
    '--no-banner',
    '--no-color',
  ];
}

/**
 * Parses raw Gitleaks JSON report output strictly in memory.
 *
 * Security Invariants:
 * - Parsed in-memory; raw stdout is never persisted or logged.
 * - If output is empty (e.g. clean exit 0), returns empty array.
 * - Throws sanitized Error if JSON is malformed (never echoes raw output in error message).
 */
export function parseGitleaksJsonOutput(stdout: string): GitleaksRawFinding[] {
  const trimmed = stdout.trim();
  if (!trimmed) {
    return [];
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(trimmed);
  } catch {
    throw new Error('Failed to parse Gitleaks output: Invalid JSON structure');
  }

  if (!Array.isArray(parsed)) {
    throw new Error('Failed to parse Gitleaks output: Expected JSON array');
  }

  return parsed as GitleaksRawFinding[];
}

/**
 * Executes a Gitleaks secret detection scan inside a hardened Stage 1 Docker container.
 *
 * Security & Isolation Invariants:
 * - Process-boundary native secret redaction via `--redact`.
 * - `--network=none` (strictly zero network access).
 * - `--read-only` root filesystem.
 * - `--tmpfs /tmp:rw,noexec,nosuid,size=64m`.
 * - Dropped capabilities (`--cap-drop=ALL`) and unprivileged user `1000:1000`.
 * - Resource limits (`--cpus=1`, `--memory=512m`, `--pids-limit=256`, 10MB stdout limit).
 * - Hard timeout with automatic container termination (`docker kill` + SIGKILL).
 * - Sensitive raw output protection: raw stdout and stderr are NEVER logged or exposed in exceptions.
 * - Exit-code semantics:
 *     - Exit 0: Clean scan (success, 0 findings)
 *     - Exit 1: Finding-positive scan (success, findings detected & parsed)
 *     - Exit >1: Operational or configuration failure
 */
export async function executeGitleaksScan(
  options: ExecuteGitleaksScanOptions
): Promise<GitleaksScannerResult> {
  const {
    scanId,
    userId,
    workspacePath,
    image = env.GITLEAKS_IMAGE,
    timeoutMs = env.GITLEAKS_TIMEOUT_MS,
    memoryLimit = env.GITLEAKS_MEMORY_LIMIT,
  } = options;

  const startTime = Date.now();

  logger.info(
    { scanId, scanner: 'gitleaks', image, timeoutMs },
    'Starting hardened Stage 1 Gitleaks secret scan'
  );

  const commandArgs = buildGitleaksCommandArgs();

  try {
    const runnerResult = await runDockerScanner({
      scanId,
      scannerName: 'gitleaks',
      workspacePath,
      image,
      commandArgs,
      timeoutMs,
      memoryLimit,
      homeTmpfs: '/home/gitleaks:rw,noexec,nosuid,size=32m,uid=1000,gid=1000',
      extraEnv: {
        HOME: '/tmp',
      },
    });

    const durationMs = runnerResult.durationMs ?? Date.now() - startTime;
    const exitCode = runnerResult.exitCode;

    // Exit code semantics:
    // 0 = clean scan (no secrets found)
    // 1 = findings detected (successful scan with leaks)
    if (exitCode === 0 || exitCode === 1) {
      let rawFindings: GitleaksRawFinding[] = [];
      try {
        rawFindings = parseGitleaksJsonOutput(runnerResult.stdout);
      } catch (parseErr) {
        logger.error(
          { scanId, scanner: 'gitleaks', exitCode },
          'Failed to parse Gitleaks output'
        );
        return {
          status: 'failed',
          scanner: 'gitleaks',
          error:
            parseErr instanceof Error
              ? parseErr.message
              : 'Failed to parse Gitleaks output',
          durationMs,
        };
      }

      // Normalize findings with double redaction and deduplication
      const normalizedResult = normalizeGitleaksOutput(scanId, userId, rawFindings);

      logger.info(
        {
          scanId,
          scanner: 'gitleaks',
          exitCode,
          matchesCount: rawFindings.length,
          normalizedCount: normalizedResult.findings.length,
          durationMs,
        },
        'Gitleaks secret scan completed successfully'
      );

      return {
        status: 'success',
        scanner: 'gitleaks',
        findings: normalizedResult.findings,
        durationMs,
        rawMatchesCount: rawFindings.length,
      };
    }

    // Exit code > 1 indicates a fatal runtime, configuration, or CLI error
    logger.warn(
      { scanId, scanner: 'gitleaks', exitCode, durationMs },
      'Gitleaks scanner exited with fatal non-zero code'
    );

    return {
      status: 'failed',
      scanner: 'gitleaks',
      error: `Gitleaks execution failed (exit code ${exitCode})`,
      durationMs,
    };
  } catch (err: unknown) {
    const durationMs = Date.now() - startTime;

    if (err instanceof ScannerTimeoutError) {
      logger.error(
        { scanId, scanner: 'gitleaks', timeoutMs },
        'Gitleaks scanner container timed out'
      );
      return {
        status: 'failed',
        scanner: 'gitleaks',
        error: `Gitleaks scan timed out after ${timeoutMs}ms`,
        durationMs,
      };
    }

    if (err instanceof OutputSizeExceededError) {
      logger.error(
        { scanId, scanner: 'gitleaks' },
        'Gitleaks scanner output exceeded buffer limit'
      );
      return {
        status: 'failed',
        scanner: 'gitleaks',
        error: err.message,
        durationMs,
      };
    }

    const errorMessage =
      err instanceof Error ? err.message : 'Unknown Gitleaks execution failure';

    logger.error(
      { scanId, scanner: 'gitleaks', error: errorMessage },
      'Gitleaks scanner encountered unexpected execution error'
    );

    return {
      status: 'failed',
      scanner: 'gitleaks',
      error: errorMessage,
      durationMs,
    };
  }
}
