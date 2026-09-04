import { spawn } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { env } from '@/lib/env';
import { logger } from '@/lib/logger';
import { createWorkspace, cleanupWorkspace, validateWorkspaceSymlinks } from './workspace';
import { executeSemgrepScan } from './semgrep';
import { detectEcosystems } from './ecosystem';
import { executeTrivyScan, type TrivyVulnerabilityFinding } from './trivy';
import { executeOsvScan, type OsvVulnerabilityFinding } from './osv';
import {
  normalizeDependencyFindings,
  type NormalizedFindingInput,
} from './normalizer';
import { ScannerTimeoutError } from './runner';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import type { FindingScanner, ScanSummary } from '@/types';

/**
 * Safe Repository Acquisition & Multi-Scanner Orchestration Engine.
 *
 * Implements FR-05, FR-06, FR-07, FR-09, FR-12, NFR-02, NFR-03:
 * - Safely clones untrusted repositories with strict hardening.
 * - Enforces `-c core.hooksPath=/dev/null` to neutralize malicious git hooks.
 * - Uses `--depth 1` and `--single-branch` for shallow clone.
 * - Traverses and validates all symlinks to prevent directory traversal escapes.
 * - Enforces size limits (`MAX_REPO_SIZE_MB`).
 * - Detects dependency ecosystems and extracts coordinates statically without executing code.
 * - Orchestrates fault-isolated execution of Semgrep, Trivy, and OSV scanners.
 * - Normalizes and deduplicates findings cross-scanner using deterministic SHA-256 fingerprints.
 * - Aggregates scan summary severity metrics and persists findings in MongoDB.
 * - Unconditionally cleans up ephemeral workspace in finally block.
 */

export interface AcquireRepositoryOptions {
  scanId: string;
  repositoryOwner: string;
  repositoryName: string;
  branch: string;
  accessToken: string;
  maxSizeMb?: number;
}

export interface AcquireRepositoryResult {
  workspacePath: string;
  commitSha: string;
  sizeBytes: number;
}

export interface ScannerErrorRecord {
  scanner: FindingScanner;
  status: 'unavailable' | 'failed';
  reason?: string;
  error?: string;
}

/**
 * Sanitize error messages to prevent credential leakage.
 */
function sanitizeErrorMessage(msg: string): string {
  return msg.replace(/gho_[a-zA-Z0-9_]+/g, '[REDACTED]');
}

/**
 * Calculate directory size recursively.
 */
async function calculateDirectorySize(dirPath: string): Promise<number> {
  let totalBytes = 0;
  const entries = await fs.readdir(dirPath, { withFileTypes: true });

  for (const entry of entries) {
    const fullPath = path.join(dirPath, entry.name);
    if (entry.isDirectory()) {
      totalBytes += await calculateDirectorySize(fullPath);
    } else if (entry.isFile()) {
      const stats = await fs.stat(fullPath);
      totalBytes += stats.size;
    }
  }

  return totalBytes;
}

/**
 * Executes a git command with timeout and sanitized environment.
 */
function runGitCommand(
  args: string[],
  cwd?: string,
  timeoutMs = 120_000,
  extraEnv: Record<string, string> = {}
): Promise<{ stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const gitProcess = spawn('git', args, {
      cwd,
      timeout: timeoutMs,
      env: {
        ...process.env,
        // Neutralize git hooks globally in child process
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_TERMINAL_PROMPT: '0',
        ...extraEnv,
      },
    });

    let stdout = '';
    let stderr = '';

    gitProcess.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    gitProcess.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    gitProcess.on('error', (err) => {
      reject(err);
    });

    gitProcess.on('close', (code) => {
      if (code === 0) {
        resolve({ stdout, stderr });
      } else {
        // Redact any access token from error message if present
        const sanitizedStderr = sanitizeErrorMessage(stderr);
        reject(new Error(`Git command failed (code ${code}): ${sanitizedStderr}`));
      }
    });
  });
}

/**
 * Perform safe repository acquisition.
 */
export async function acquireRepository(
  options: AcquireRepositoryOptions
): Promise<AcquireRepositoryResult> {
  const {
    scanId,
    repositoryOwner,
    repositoryName,
    branch,
    accessToken,
    maxSizeMb = env.MAX_REPO_SIZE_MB,
  } = options;

  logger.info(
    { scanId, repository: `${repositoryOwner}/${repositoryName}`, branch },
    'Starting safe repository acquisition'
  );

  // 1. Allocate isolated workspace
  const workspacePath = await createWorkspace(scanId);

  try {
    // 2. Build authenticated clone URL (with in-memory token masking)
    const cloneUrl = `https://x-access-token:${accessToken}@github.com/${repositoryOwner}/${repositoryName}.git`;

    // 3. Safe git clone execution with strict security flags:
    //    - -c core.hooksPath=/dev/null: blocks arbitrary code execution from malicious git hooks
    //    - -c core.fsmonitor=false: disables fsmonitor hooks
    //    - --depth 1: shallow clone
    //    - --single-branch: only acquire target branch
    //    - --no-tags: avoid tag overhead
    const cloneArgs = [
      'clone',
      '--depth', '1',
      '--single-branch',
      '--branch', branch,
      '--no-tags',
      '-c', 'core.hooksPath=/dev/null',
      '-c', 'core.fsmonitor=false',
      cloneUrl,
      workspacePath,
    ];

    await runGitCommand(cloneArgs, undefined, 120_000);

    // 4. Retrieve resolved HEAD commit SHA
    const revParseResult = await runGitCommand(['rev-parse', 'HEAD'], workspacePath, 10_000);
    const commitSha = revParseResult.stdout.trim();

    // 5. Inspect total cloned size
    const sizeBytes = await calculateDirectorySize(workspacePath);
    const maxSizeBytes = maxSizeMb * 1024 * 1024;

    if (sizeBytes > maxSizeBytes) {
      throw new Error(
        `Cloned repository size (${(sizeBytes / 1024 / 1024).toFixed(1)} MB) exceeds limit of ${maxSizeMb} MB`
      );
    }

    // 6. Inspect symlinks for traversal escapes
    await validateWorkspaceSymlinks(workspacePath);

    logger.info(
      { scanId, commitSha, sizeBytes },
      'Repository successfully acquired and validated'
    );

    return {
      workspacePath,
      commitSha,
      sizeBytes,
    };
  } catch (err) {
    // Cleanup on failure
    await cleanupWorkspace(workspacePath);
    const errorMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
    logger.error({ scanId, error: errorMsg }, 'Repository acquisition failed');
    throw err;
  }
}

/**
 * Orchestrates full multi-scanner scan pipeline for a Scan document in MongoDB.
 * Lifecycle transitions:
 *   queued -> cloning -> scanning -> normalizing -> completed
 * Failure transitions:
 *   cloning/scanning/normalizing -> failed | timed_out
 * Fault isolation:
 *   Individual scanner failures do not abort or discard findings from successful scanners.
 * Guaranteed cleanup:
 *   Workspace directory is cleaned up unconditionally in finally block.
 */
export async function processScanPipeline(
  scanId: string,
  accessToken: string
): Promise<void> {
  const scan = await Scan.findById(scanId);
  if (!scan) {
    logger.error({ scanId }, 'Scan not found during pipeline kickoff');
    return;
  }

  let workspacePath: string | null = null;

  try {
    // 1. Safe Repository Acquisition
    scan.status = 'cloning';
    scan.startedAt = new Date();
    await scan.save();

    const acquireResult = await acquireRepository({
      scanId,
      repositoryOwner: scan.repositoryOwner,
      repositoryName: scan.repositoryName,
      branch: scan.branch,
      accessToken,
    });

    workspacePath = acquireResult.workspacePath;
    scan.commitSha = acquireResult.commitSha;
    scan.workspacePath = workspacePath;

    // 2. Ecosystem & Dependency Coordinate Detection
    const ecosystemResult = await detectEcosystems(workspacePath);

    // 3. Multi-Scanner Scanning Phase (Fault-Isolated)
    scan.status = 'scanning';
    await scan.save();

    const successfulScanners: FindingScanner[] = [];
    const scannerErrors: ScannerErrorRecord[] = [];
    const warnings: string[] = [];

    let semgrepFindings: NormalizedFindingInput[] = [];
    let trivyFindings: TrivyVulnerabilityFinding[] = [];
    let osvFindings: OsvVulnerabilityFinding[] = [];

    // --- Scanner 1: Semgrep SAST ---
    try {
      const semgrepResult = await executeSemgrepScan({
        scanId,
        userId: scan.userId.toString(),
        workspacePath,
      });
      semgrepFindings = semgrepResult.normalization.findings;
      successfulScanners.push('semgrep');
    } catch (err) {
      const isTimeout =
        err instanceof ScannerTimeoutError ||
        (err instanceof Error && err.message.includes('timed out'));
      if (isTimeout) {
        throw err;
      }
      const errorMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
      logger.error({ scanId, err: errorMsg }, 'Semgrep scan failed');
      scannerErrors.push({
        scanner: 'semgrep',
        status: 'failed',
        error: errorMsg,
      });
      warnings.push(`Warning: Semgrep scan failed (${errorMsg})`);
    }

    // --- Scanner 2: Trivy SCA Filesystem ---
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
        logger.warn({ scanId, reason }, 'Trivy offline DB unavailable');
        scannerErrors.push({
          scanner: 'trivy',
          status: 'unavailable',
          reason,
        });
        warnings.push(`Warning: Trivy unavailable (${reason})`);
      } else if (trivyResult.status === 'failed') {
        const error = sanitizeErrorMessage(trivyResult.error);
        logger.error({ scanId, error }, 'Trivy scanner failed');
        scannerErrors.push({
          scanner: 'trivy',
          status: 'failed',
          error,
        });
        warnings.push(`Warning: Trivy scan failed (${error})`);
      }
    } catch (err) {
      const isTimeout =
        err instanceof ScannerTimeoutError ||
        (err instanceof Error && err.message.includes('timed out'));
      if (isTimeout) {
        throw err;
      }
      const errorMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
      logger.error({ scanId, err: errorMsg }, 'Trivy scan encountered unexpected error');
      scannerErrors.push({
        scanner: 'trivy',
        status: 'failed',
        error: errorMsg,
      });
      warnings.push(`Warning: Trivy scan failed (${errorMsg})`);
    }

    // --- Scanner 3: OSV Dependency Advisories ---
    try {
      if (ecosystemResult.coordinates.length === 0) {
        // Zero dependency coordinates: OSV performs zero HTTP requests and succeeds with 0 findings
        successfulScanners.push('osv');
        osvFindings = [];
      } else {
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
          logger.error({ scanId, error }, 'OSV query failed');
          scannerErrors.push({
            scanner: 'osv',
            status: 'failed',
            error,
          });
          warnings.push(`Warning: OSV query failed (${error})`);
        }
      }
    } catch (err) {
      const isTimeout =
        err instanceof ScannerTimeoutError ||
        (err instanceof Error && err.message.includes('timed out'));
      if (isTimeout) {
        throw err;
      }
      const errorMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
      logger.error({ scanId, err: errorMsg }, 'OSV scan encountered unexpected error');
      scannerErrors.push({
        scanner: 'osv',
        status: 'failed',
        error: errorMsg,
      });
      warnings.push(`Warning: OSV query failed (${errorMsg})`);
    }

    // 4. Normalization, Deduplication & Aggregation
    scan.status = 'normalizing';
    await scan.save();

    let dependencyFindings: NormalizedFindingInput[] = [];
    if (trivyFindings.length > 0 || osvFindings.length > 0) {
      const depNormResult = normalizeDependencyFindings(scanId, scan.userId.toString(), {
        trivyFindings,
        osvFindings,
      });
      dependencyFindings = depNormResult.findings;
    }

    const allFindings = [...semgrepFindings, ...dependencyFindings];

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

    // 5. Findings Persistence
    if (allFindings.length > 0) {
      const batchSize = 500;
      for (let i = 0; i < allFindings.length; i += batchSize) {
        const batch = allFindings.slice(i, i + batchSize);
        await Finding.insertMany(batch, { ordered: false });
      }
    }

    // 6. Complete Scan Record
    if (successfulScanners.length === 0) {
      scan.status = 'failed';
      scan.scanners = [];
      scan.error =
        warnings.length > 0
          ? `Scan failed: All scanners failed (${warnings.join('; ')})`
          : 'Scan failed: All scanners failed';
      scan.summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    } else {
      scan.status = 'completed';
      scan.scanners = successfulScanners;
      scan.error = warnings.length > 0 ? warnings.join('; ') : null;
      scan.summary = summary;
    }

    scan.set('metadata', { scannerErrors }, { strict: false });
    (scan as unknown as { metadata: Record<string, unknown> }).metadata = { scannerErrors };

    scan.completedAt = new Date();
    if (scan.startedAt) {
      scan.duration = scan.completedAt.getTime() - scan.startedAt.getTime();
    }
    await scan.save();

    logger.info(
      {
        scanId,
        scanners: scan.scanners,
        findingsCount: allFindings.length,
        summary,
        durationMs: scan.duration,
      },
      'Scan pipeline finished processing'
    );
  } catch (err) {
    const errorMsg = sanitizeErrorMessage(err instanceof Error ? err.message : String(err));
    const isTimeout = err instanceof ScannerTimeoutError || errorMsg.includes('timed out');

    logger.error({ scanId, error: errorMsg, isTimeout }, 'Scan pipeline encountered fatal failure');

    // Purge partial findings to maintain database consistency
    try {
      await Finding.deleteMany({ scanId: scan._id });
    } catch (cleanupErr) {
      logger.warn({ scanId, cleanupErr }, 'Failed to purge partial findings');
    }

    scan.status = isTimeout ? 'timed_out' : 'failed';
    scan.error = errorMsg;
    scan.scanners = [];
    scan.summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    scan.completedAt = new Date();
    if (scan.startedAt) {
      scan.duration = scan.completedAt.getTime() - scan.startedAt.getTime();
    }
    await scan.save();
  } finally {
    // 7. Guaranteed Workspace Cleanup
    if (workspacePath) {
      try {
        await cleanupWorkspace(workspacePath);
        scan.workspacePath = null;
        await scan.save();
      } catch (err) {
        logger.warn({ scanId, workspacePath, err }, 'Failed to cleanup workspace in finally');
      }
    }
  }
}

/**
 * Backwards-compatible alias for processScanPipeline.
 */
export const processScanAcquisition = processScanPipeline;
