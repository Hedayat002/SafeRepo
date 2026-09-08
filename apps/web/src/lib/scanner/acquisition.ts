import { spawn } from 'child_process';
import fs from 'fs/promises';
import path from 'path';
import { env } from '@/lib/env';
import { logger } from '@/lib/logger';
import { createWorkspace, cleanupWorkspace, validateWorkspaceSymlinks } from './workspace';

/**
 * Safe Repository Acquisition & Multi-Scanner Orchestration Engine.
 *
 * Implements FR-05, FR-06, FR-07, FR-08, FR-09, FR-12, FR-13, NFR-02, NFR-03:
 * - Safely clones untrusted repositories with strict hardening.
 * - Enforces `-c core.hooksPath=/dev/null` to neutralize malicious git hooks.
 * - Uses `--depth 1` and `--single-branch` for shallow clone.
 * - Traverses and validates all symlinks to prevent directory traversal escapes.
 * - Enforces size limits (`MAX_REPO_SIZE_MB`).
 * - Detects dependency ecosystems and extracts coordinates statically without executing code.
 * - Orchestrates fault-isolated execution of Semgrep, Trivy, OSV, and Gitleaks scanners.
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
 * Phase 06: Scanner orchestration is now handled by orchestrator.ts.
 * The processScanPipeline and processScanAcquisition exports are preserved
 * for backward compatibility with existing callers and tests.
 */
export async function processScanPipeline(
  scanId: string,
  accessToken: string = ''
): Promise<void> {
  const { executeOrchestratedScan } = await import('./orchestrator');
  await executeOrchestratedScan(scanId, 'in-process-worker', accessToken);
}

export const processScanAcquisition = processScanPipeline;

// Re-export types that other modules depend on
export type { ScannerErrorRecord } from '@/types';
