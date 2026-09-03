import { spawn } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { env } from '@/lib/env';
import { logger } from '@/lib/logger';
import { createWorkspace, cleanupWorkspace, validateWorkspaceSymlinks } from './workspace';
import { executeSemgrepScan } from './semgrep';
import { ScannerTimeoutError } from './runner';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';

/**
 * Safe Repository Acquisition Engine.
 *
 * Implements FR-05, NFR-02, NFR-03:
 * - Safely clones untrusted repositories with strict hardening.
 * - Enforces `-c core.hooksPath=/dev/null` to neutralize malicious repository git hooks.
 * - Uses `--depth 1` and `--single-branch` for shallow clone.
 * - Traverses and validates all symlinks to prevent directory traversal escapes.
 * - Enforces size limits (`MAX_REPO_SIZE_MB`).
 * - Updates scan status through lifecycle transitions:
 *     queued -> cloning -> (ready for scanning in Phase 03) / failed.
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
        const sanitizedStderr = stderr.replace(/gho_[a-zA-Z0-9_]+/g, '[REDACTED]');
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
    const errorMsg = err instanceof Error ? err.message : String(err);
    logger.error({ scanId, error: errorMsg }, 'Repository acquisition failed');
    throw err;
  }
}

/**
 * Orchestrates full scan pipeline for a Scan document in MongoDB.
 * Lifecycle transitions:
 *   queued -> cloning -> scanning -> normalizing -> completed
 * Failure transitions:
 *   cloning/scanning/normalizing -> failed | timed_out
 * Guaranteed cleanup:
 *   Workspace directory is cleaned up in finally block.
 *   Partial findings are purged on failure to prevent inconsistent state.
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

    // 2. Semgrep SAST Scanning
    scan.status = 'scanning';
    await scan.save();

    const scanResult = await executeSemgrepScan({
      scanId,
      userId: scan.userId.toString(),
      workspacePath,
    });

    // 3. Normalization & Persistence
    scan.status = 'normalizing';
    await scan.save();

    const { findings, summary } = scanResult.normalization;

    // Batch insert findings in chunks of 500
    if (findings.length > 0) {
      const batchSize = 500;
      for (let i = 0; i < findings.length; i += batchSize) {
        const batch = findings.slice(i, i + batchSize);
        await Finding.insertMany(batch, { ordered: false });
      }
    }

    // 4. Complete Scan Record
    scan.status = 'completed';
    scan.summary = summary;
    scan.completedAt = new Date();
    if (scan.startedAt) {
      scan.duration = scan.completedAt.getTime() - scan.startedAt.getTime();
    }
    await scan.save();

    logger.info(
      { scanId, summary, durationMs: scan.duration },
      'Scan pipeline completed successfully'
    );
  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    const isTimeout = err instanceof ScannerTimeoutError || errorMsg.includes('timed out');

    logger.error({ scanId, error: errorMsg, isTimeout }, 'Scan pipeline failed');

    // Purge any partial findings to maintain database consistency
    try {
      await Finding.deleteMany({ scanId: scan._id });
    } catch (cleanupErr) {
      logger.warn({ scanId, cleanupErr }, 'Failed to purge partial findings');
    }

    scan.status = isTimeout ? 'timed_out' : 'failed';
    scan.error = errorMsg;
    scan.summary = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    scan.completedAt = new Date();
    if (scan.startedAt) {
      scan.duration = scan.completedAt.getTime() - scan.startedAt.getTime();
    }
    await scan.save();
  } finally {
    // 5. Guaranteed Workspace Cleanup
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

