import { env } from '@/lib/env';
import { logger } from '@/lib/logger';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import { acquireRepository } from './acquisition';
import { executeSemgrepScan } from './semgrep';
import { detectEcosystems } from './ecosystem';
import { executeTrivyScan, type TrivyVulnerabilityFinding } from './trivy';
import { executeOsvScan, type OsvVulnerabilityFinding } from './osv';
import { executeGitleaksScan } from './gitleaks';
import {
  normalizeDependencyFindings,
  type NormalizedFindingInput,
} from './normalizer';
import { ScannerTimeoutError, killDockerContainer } from './runner';
import { cleanupWorkspace } from './workspace';
import { transitionScanStatus } from './queue';
import type {
  FindingScanner,
  ScanSummary,
  ScannerErrorRecord,
  OrchestratorResult,
} from '@/types';

/**
 * Phase 06 — Unified Multi-Scanner Orchestrator
 *
 * Coordinates sequential execution of Semgrep, Trivy, OSV, and Gitleaks
 * under a single global deadline with:
 * - Active container tracking for deterministic abort
 * - AbortController-driven global timeout
 * - Fault-isolated scanner execution
 * - Master normalization and cross-scanner deduplication
 * - Leased state transitions with heartbeat updates
 *
 * Security invariants preserved:
 * - Stage 1 container hardening (--network=none, --read-only, etc.)
 * - Zero plaintext secret logging
 * - Docker socket restricted to runner
 */

/**
 * Sanitize error messages to prevent credential leakage.
 */
function sanitizeErrorMessage(msg: string): string {
  return msg.replace(/gho_[a-zA-Z0-9_]+/g, '[REDACTED]');
}

/**
 * Compute remaining time budget from the global deadline.
 */
function getRemainingMs(deadline: number): number {
  return Math.max(0, deadline - Date.now());
}

/**
 * Compute effective timeout for a child scanner, capped by global deadline.
 */
function getEffectiveTimeout(scannerTimeoutMs: number, deadline: number): number {
  const remaining = getRemainingMs(deadline);
  return Math.min(scannerTimeoutMs, remaining);
}

/**
 * Executes the full scan pipeline for a claimed scan job.
 *
 * Lifecycle:
 *   cloning → scanning → normalizing → completed
 *   Any stage can transition to failed or timed_out
 *
 * @param scanId - MongoDB Scan document ID
 * @param workerId - Worker instance ID for lease verification
 * @param accessToken - GitHub access token for repository cloning
 */
export async function executeOrchestratedScan(
  scanId: string,
  workerId: string = 'in-process-worker',
  accessToken: string = ''
): Promise<OrchestratorResult> {
  const startTime = Date.now();
  const config = {
    scanTimeoutSeconds: env.SCAN_TIMEOUT_SECONDS,
  };

  const globalDeadlineMs = startTime + config.scanTimeoutSeconds * 1000;

  // AbortController for global timeout
  const abortController = new AbortController();
  const abortSignal = abortController.signal;

  // Global timeout timer
  const globalTimer = setTimeout(() => {
    abortController.abort();
  }, config.scanTimeoutSeconds * 1000);
  globalTimer.unref();

  // Active container tracking for cleanup on abort
  const activeContainers = new Set<string>();

  const scan = await Scan.findById(scanId);
  if (!scan) {
    clearTimeout(globalTimer);
    return {
      status: 'failed',
      scanners: [],
      findingsCount: 0,
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      warnings: [],
      scannerErrors: [],
      error: 'Scan not found',
      durationMs: Date.now() - startTime,
    };
  }

  // If scan is still queued, claim it for this worker and transition to cloning
  if (scan.status === 'queued') {
    const claimed = await Scan.findOneAndUpdate(
      { _id: scanId, status: 'queued' },
      {
        $set: {
          status: 'cloning',
          workerId,
          startedAt: new Date(),
          heartbeatAt: new Date(),
        },
      },
      { returnDocument: 'after' }
    );
    if (!claimed) {
      clearTimeout(globalTimer);
      return {
        status: 'failed',
        scanners: [],
        findingsCount: 0,
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        warnings: [],
        scannerErrors: [],
        error: 'Scan was already claimed or transitioned by another worker',
        durationMs: Date.now() - startTime,
      };
    }
  }

  let workspacePath: string | null = null;
  const successfulScanners: FindingScanner[] = [];
  const scannerErrors: ScannerErrorRecord[] = [];
  const warnings: string[] = [];

  /**
   * Abort handler: kill all active containers and clean up on global timeout.
   */
  async function handleGlobalTimeout(): Promise<OrchestratorResult> {
    logger.error(
      { scanId, elapsedMs: Date.now() - startTime },
      'Global scan deadline expired — aborting all active containers'
    );

    // Kill all tracked containers
    for (const containerName of activeContainers) {
      try {
        await killDockerContainer(containerName);
      } catch (err) {
        logger.warn({ scanId, containerName, err }, 'Failed to kill container on timeout');
      }
    }
    activeContainers.clear();

    // Purge partial findings
    try {
      await Finding.deleteMany({ scanId });
    } catch (err) {
      logger.warn({ scanId, err }, 'Failed to purge partial findings on timeout');
    }

    // Transition to timed_out
    const currentStatus = scan?.status ?? 'scanning';
    const errorMsg = `Scan exceeded maximum duration of ${config.scanTimeoutSeconds}s`;
    await transitionScanStatus(scanId, workerId, currentStatus, 'timed_out', {
      error: errorMsg,
      completedAt: new Date(),
      duration: Date.now() - startTime,
      scanners: [],
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
    });

    return {
      status: 'timed_out',
      scanners: [],
      findingsCount: 0,
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      warnings,
      scannerErrors,
      error: errorMsg,
      durationMs: Date.now() - startTime,
    };
  }

  try {
    // ─── Stage 1: Repository Acquisition (cloning) ───

    if (getRemainingMs(globalDeadlineMs) <= 0 || abortSignal.aborted) {
      return await handleGlobalTimeout();
    }

    const acquireResult = await acquireRepository({
      scanId,
      repositoryOwner: scan.repositoryOwner,
      repositoryName: scan.repositoryName,
      branch: scan.branch,
      accessToken,
    });

    workspacePath = acquireResult.workspacePath;

    // Update scan with acquisition results
    await Scan.findOneAndUpdate(
      { _id: scanId, workerId },
      {
        $set: {
          commitSha: acquireResult.commitSha,
          workspacePath,
        },
      }
    );

    // Transition to scanning
    const scanningTransition = await transitionScanStatus(
      scanId, workerId, 'cloning', 'scanning', {}
    );

    if (!scanningTransition) {
      logger.warn({ scanId, workerId }, 'Failed to transition to scanning — lease lost');
      return {
        status: 'failed',
        scanners: [],
        findingsCount: 0,
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        warnings: [],
        scannerErrors: [],
        error: 'Worker lease lost during cloning',
        durationMs: Date.now() - startTime,
      };
    }

    // ─── Stage 2: Multi-Scanner Execution (scanning) ───

    // Detect ecosystems for OSV
    const ecosystemResult = await detectEcosystems(workspacePath);

    let semgrepFindings: NormalizedFindingInput[] = [];
    let trivyFindings: TrivyVulnerabilityFinding[] = [];
    let osvFindings: OsvVulnerabilityFinding[] = [];
    let gitleaksFindings: NormalizedFindingInput[] = [];

    // --- Scanner 1: Semgrep SAST ---
    if (getRemainingMs(globalDeadlineMs) > 0 && !abortSignal.aborted) {
      const containerName = `saferepo-scan-${scanId}-semgrep`;
      activeContainers.add(containerName);
      try {
        const effectiveTimeout = getEffectiveTimeout(env.SEMGREP_TIMEOUT_MS, globalDeadlineMs);
        if (effectiveTimeout <= 0) {
          throw new ScannerTimeoutError('No time remaining for Semgrep');
        }
        const semgrepResult = await executeSemgrepScan({
          scanId,
          userId: scan.userId.toString(),
          workspacePath,
        });
        semgrepFindings = semgrepResult.normalization.findings;
        successfulScanners.push('semgrep');
      } catch (err) {
        if (abortSignal.aborted) {
          return await handleGlobalTimeout();
        }
        const isTimeout =
          err instanceof ScannerTimeoutError ||
          (err instanceof Error && err.message.includes('timed out'));
        if (isTimeout) {
          throw err;
        }
        const errorMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
        logger.error({ scanId, err: errorMsg }, 'Semgrep scan failed');
        scannerErrors.push({ scanner: 'semgrep', status: 'failed', error: errorMsg });
        warnings.push(`Warning: Semgrep scan failed (${errorMsg})`);
      } finally {
        activeContainers.delete(containerName);
      }
    }

    // --- Scanner 2: Trivy SCA ---
    if (getRemainingMs(globalDeadlineMs) > 0 && !abortSignal.aborted) {
      const containerName = `saferepo-scan-${scanId}-trivy`;
      activeContainers.add(containerName);
      try {
        const trivyResult = await executeTrivyScan({
          scanId,
          userId: scan.userId.toString(),
          workspacePath,
        });

        if (trivyResult.status === 'success') {
          successfulScanners.push('trivy');
          trivyFindings = trivyResult.findings;
        } else if (trivyResult.status === 'unavailable') {
          const reason = sanitizeErrorMessage(trivyResult.reason);
          scannerErrors.push({ scanner: 'trivy', status: 'unavailable', reason });
          warnings.push(`Warning: Trivy unavailable (${reason})`);
        } else if (trivyResult.status === 'failed') {
          const error = sanitizeErrorMessage(trivyResult.error);
          scannerErrors.push({ scanner: 'trivy', status: 'failed', error });
          warnings.push(`Warning: Trivy scan failed (${error})`);
        }
      } catch (err) {
        if (abortSignal.aborted) {
          return await handleGlobalTimeout();
        }
        const isTimeout =
          err instanceof ScannerTimeoutError ||
          (err instanceof Error && err.message.includes('timed out'));
        if (isTimeout) {
          throw err;
        }
        const errorMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
        logger.error({ scanId, err: errorMsg }, 'Trivy scan failed');
        scannerErrors.push({ scanner: 'trivy', status: 'failed', error: errorMsg });
        warnings.push(`Warning: Trivy scan failed (${errorMsg})`);
      } finally {
        activeContainers.delete(containerName);
      }
    }

    // --- Scanner 3: OSV Dependency Advisories ---
    if (getRemainingMs(globalDeadlineMs) > 0 && !abortSignal.aborted) {
      try {
        if (ecosystemResult.coordinates.length === 0) {
          successfulScanners.push('osv');
          osvFindings = [];
        } else {
          const effectiveTimeout = getEffectiveTimeout(env.OSV_TIMEOUT_MS, globalDeadlineMs);
          if (effectiveTimeout <= 0) {
            throw new ScannerTimeoutError('No time remaining for OSV');
          }
          const osvResult = await executeOsvScan({
            scanId,
            userId: scan.userId.toString(),
            coordinates: ecosystemResult.coordinates,
          });

          if (osvResult.status === 'success') {
            successfulScanners.push('osv');
            osvFindings = osvResult.findings;
          } else if (osvResult.status === 'failed') {
            const error = sanitizeErrorMessage(osvResult.error);
            scannerErrors.push({ scanner: 'osv', status: 'failed', error });
            warnings.push(`Warning: OSV query failed (${error})`);
          }
        }
      } catch (err) {
        if (abortSignal.aborted) {
          return await handleGlobalTimeout();
        }
        const isTimeout =
          err instanceof ScannerTimeoutError ||
          (err instanceof Error && err.message.includes('timed out'));
        if (isTimeout) {
          throw err;
        }
        const errorMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
        logger.error({ scanId, err: errorMsg }, 'OSV scan failed');
        scannerErrors.push({ scanner: 'osv', status: 'failed', error: errorMsg });
        warnings.push(`Warning: OSV query failed (${errorMsg})`);
      }
    }

    // --- Scanner 4: Gitleaks Secret Scanner ---
    if (getRemainingMs(globalDeadlineMs) > 0 && !abortSignal.aborted) {
      const containerName = `saferepo-scan-${scanId}-gitleaks`;
      activeContainers.add(containerName);
      try {
        const gitleaksResult = await executeGitleaksScan({
          scanId,
          userId: scan.userId.toString(),
          workspacePath,
        });

        if (gitleaksResult.status === 'success') {
          successfulScanners.push('gitleaks');
          gitleaksFindings = gitleaksResult.findings;
        } else if (gitleaksResult.status === 'failed') {
          const error = sanitizeErrorMessage(gitleaksResult.error);
          scannerErrors.push({ scanner: 'gitleaks', status: 'failed', error });
          warnings.push(`Warning: Gitleaks scan failed (${error})`);
        }
      } catch (err) {
        if (abortSignal.aborted) {
          return await handleGlobalTimeout();
        }
        const isTimeout =
          err instanceof ScannerTimeoutError ||
          (err instanceof Error && err.message.includes('timed out'));
        if (isTimeout) {
          throw err;
        }
        const errorMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
        logger.error({ scanId, err: errorMsg }, 'Gitleaks scan failed');
        scannerErrors.push({ scanner: 'gitleaks', status: 'failed', error: errorMsg });
        warnings.push(`Warning: Gitleaks scan failed (${errorMsg})`);
      } finally {
        activeContainers.delete(containerName);
      }
    }

    // Check for global timeout before normalization
    if (abortSignal.aborted || getRemainingMs(globalDeadlineMs) <= 0) {
      return await handleGlobalTimeout();
    }

    // ─── Stage 3: Normalization & Persistence (normalizing) ───

    const normTransition = await transitionScanStatus(
      scanId, workerId, 'scanning', 'normalizing', {}
    );
    if (!normTransition) {
      logger.warn({ scanId, workerId }, 'Failed to transition to normalizing — lease lost');
      return {
        status: 'failed',
        scanners: [],
        findingsCount: 0,
        summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        warnings,
        scannerErrors,
        error: 'Worker lease lost during scanning',
        durationMs: Date.now() - startTime,
      };
    }

    // Master normalization
    let dependencyFindings: NormalizedFindingInput[] = [];
    if (trivyFindings.length > 0 || osvFindings.length > 0) {
      const depNormResult = normalizeDependencyFindings(scanId, scan.userId.toString(), {
        trivyFindings,
        osvFindings,
      });
      dependencyFindings = depNormResult.findings;
    }

    const allFindings = [...semgrepFindings, ...dependencyFindings, ...gitleaksFindings];

    const summary: ScanSummary = {
      total: allFindings.length,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };
    for (const finding of allFindings) {
      summary[finding.severity]++;
    }

    // Chunked batch persistence with idempotent deduplication
    if (allFindings.length > 0) {
      const batchSize = 500;
      for (let i = 0; i < allFindings.length; i += batchSize) {
        const batch = allFindings.slice(i, i + batchSize);
        try {
          await Finding.insertMany(batch, { ordered: false });
        } catch (err: unknown) {
          // Ignore duplicate key errors (E11000) for idempotent persistence
          const mongoErr = err as { code?: number; writeErrors?: Array<{ code: number }> };
          if (mongoErr.code === 11000 || mongoErr.writeErrors?.every((e) => e.code === 11000)) {
            logger.info({ scanId, batchIndex: i }, 'Duplicate findings deduplicated during batch insert');
          } else {
            throw err;
          }
        }
      }
    }

    // Determine final status
    const durationMs = Date.now() - startTime;
    let finalStatus: 'completed' | 'failed';
    let finalError: string | null = null;

    if (successfulScanners.length === 0) {
      finalStatus = 'failed';
      finalError = warnings.length > 0
        ? `Scan failed: All scanners failed (${warnings.join('; ')})`
        : 'Scan failed: All scanners failed';
    } else {
      finalStatus = 'completed';
      finalError = warnings.length > 0 ? warnings.join('; ') : null;
    }

    // Final transition
    await transitionScanStatus(scanId, workerId, 'normalizing', finalStatus, {
      scanners: successfulScanners,
      summary,
      error: finalError,
      completedAt: new Date(),
      duration: durationMs,
      metadata: { scannerErrors },
    });

    // Ensure scanner error metadata is stored on the document
    if (scannerErrors.length > 0) {
      await Scan.findByIdAndUpdate(scanId, {
        $set: { metadata: { scannerErrors } },
      });
    }

    logger.info(
      {
        scanId,
        status: finalStatus,
        scanners: successfulScanners,
        findingsCount: allFindings.length,
        summary,
        durationMs,
      },
      'Orchestrator completed scan pipeline'
    );

    clearTimeout(globalTimer);

    return {
      status: finalStatus,
      scanners: successfulScanners,
      findingsCount: allFindings.length,
      summary,
      warnings,
      scannerErrors,
      error: finalError ?? undefined,
      durationMs,
    };
  } catch (err) {
    clearTimeout(globalTimer);

    // Check if this is a global timeout
    if (abortSignal.aborted) {
      const result = await handleGlobalTimeout();
      return result;
    }

    const errorMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
    const isTimeout = err instanceof ScannerTimeoutError || errorMsg.includes('timed out');

    logger.error({ scanId, error: errorMsg, isTimeout }, 'Orchestrator encountered fatal failure');

    // Purge partial findings
    try {
      await Finding.deleteMany({ scanId: scan._id });
    } catch (cleanupErr) {
      logger.warn({ scanId, cleanupErr }, 'Failed to purge partial findings');
    }

    // Kill any active containers
    for (const containerName of activeContainers) {
      try {
        await killDockerContainer(containerName);
      } catch (killErr) {
        logger.warn({ scanId, containerName, killErr }, 'Failed to kill container on error');
      }
    }
    activeContainers.clear();

    const failStatus = isTimeout ? 'timed_out' : 'failed';
    const durationMs = Date.now() - startTime;

    // Transition to failed/timed_out from whatever state we're in
    const currentScan = await Scan.findById(scanId);
    if (currentScan && currentScan.workerId === workerId) {
      await Scan.findOneAndUpdate(
        { _id: scanId, workerId, status: { $in: ['cloning', 'scanning', 'normalizing'] } },
        {
          $set: {
            status: failStatus,
            error: errorMsg,
            scanners: [],
            summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
            completedAt: new Date(),
            duration: durationMs,
          },
        }
      );
    }

    return {
      status: failStatus as 'failed' | 'timed_out',
      scanners: [],
      findingsCount: 0,
      summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      warnings,
      scannerErrors,
      error: errorMsg,
      durationMs,
    };
  } finally {
    clearTimeout(globalTimer);

    // Guaranteed workspace cleanup
    if (workspacePath) {
      try {
        await cleanupWorkspace(workspacePath);
        await Scan.findOneAndUpdate(
          { _id: scanId, workerId },
          { $set: { workspacePath: null } }
        );
      } catch (err) {
        logger.warn({ scanId, workspacePath, err }, 'Failed to cleanup workspace in finally');
      }
    }
  }
}
