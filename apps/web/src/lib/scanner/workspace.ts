import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import { env } from '@/lib/env';
import { logger } from '@/lib/logger';

/**
 * Workspace Manager for SafeRepo.
 *
 * Responsibilities:
 * - Allocates isolated ephemeral directories for untrusted repository cloning.
 * - Enforces symlink validation so untrusted repos cannot escape workspace bounds.
 * - Safely sweeps and cleans up temporary workspaces.
 * - Provides recovery mechanisms for stale/orphaned workspaces.
 */

/**
 * Resolve base workspace root directory.
 */
export function getWorkspaceBaseDir(): string {
  if (env.SCAN_WORKSPACE_DIR) {
    return path.resolve(env.SCAN_WORKSPACE_DIR);
  }
  return path.join(os.tmpdir(), 'saferepo-workspaces');
}

/**
 * Allocate an isolated workspace directory for a specific scan.
 */
export async function createWorkspace(scanId: string): Promise<string> {
  const baseDir = getWorkspaceBaseDir();
  const workspacePath = path.join(baseDir, scanId);

  // Create base directory and scan directory if not present
  await fs.mkdir(workspacePath, { recursive: true });

  logger.debug({ scanId, workspacePath }, 'Created isolated scan workspace');
  return workspacePath;
}

/**
 * Safely delete an entire workspace directory.
 */
export async function cleanupWorkspace(workspacePath: string): Promise<void> {
  try {
    const baseDir = getWorkspaceBaseDir();
    const resolvedPath = path.resolve(workspacePath);

    // Guard: Ensure we never delete outside the workspace base dir
    if (!resolvedPath.startsWith(baseDir)) {
      logger.error(
        { workspacePath, baseDir },
        'Attempted to delete directory outside workspace base path'
      );
      throw new Error('Unsafe workspace deletion attempt');
    }

    await fs.rm(resolvedPath, { recursive: true, force: true });
    logger.debug({ workspacePath: resolvedPath }, 'Cleaned up scan workspace');
  } catch (err) {
    logger.warn({ err, workspacePath }, 'Failed to cleanly remove workspace');
  }
}

/**
 * Deep symlink traversal auditor.
 *
 * Untrusted repositories may embed symlinks targeting arbitrary files outside
 * the workspace (e.g. symlink -> /etc/passwd or symlink -> ../../.env).
 * This inspects all files recursively. If any symlink target resolves outside
 * the workspace boundary, an error is thrown.
 */
export async function validateWorkspaceSymlinks(workspacePath: string): Promise<void> {
  const resolvedBase = await fs.realpath(workspacePath);

  async function checkDir(currentDir: string): Promise<void> {
    const entries = await fs.readdir(currentDir, { withFileTypes: true });

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      if (entry.isSymbolicLink()) {
        try {
          const resolvedTarget = await fs.realpath(fullPath);

          // Check if resolved link escapes workspace
          if (!resolvedTarget.startsWith(resolvedBase + path.sep) && resolvedTarget !== resolvedBase) {
            throw new Error(
              `Malicious symlink escape detected: ${entry.name} resolves to ${resolvedTarget}`
            );
          }
        } catch (err: unknown) {
          // Broken symlink or escape error
          const msg = err instanceof Error ? err.message : String(err);
          if (msg.includes('Malicious symlink escape')) {
            throw err;
          }
          // Broken internal symlinks are not fatal, but log warning
          logger.debug({ fullPath, error: msg }, 'Ignoring unresolvable/broken symlink in repository');
        }
      } else if (entry.isDirectory()) {
        // Skip .git directory traversal for performance
        if (entry.name !== '.git') {
          await checkDir(fullPath);
        }
      }
    }
  }

  await checkDir(resolvedBase);
}

/**
 * Sweeps and cleans up stale orphaned workspaces (e.g. left behind by crashes).
 * Workspaces older than maxAgeMs are removed.
 */
export async function cleanupOrphanedWorkspaces(maxAgeMs = 3_600_000): Promise<number> {
  const baseDir = getWorkspaceBaseDir();
  let cleanedCount = 0;

  try {
    const exists = await fs
      .access(baseDir)
      .then(() => true)
      .catch(() => false);

    if (!exists) return 0;

    const entries = await fs.readdir(baseDir, { withFileTypes: true });
    const now = Date.now();

    for (const entry of entries) {
      if (entry.isDirectory()) {
        const dirPath = path.join(baseDir, entry.name);
        try {
          const stats = await fs.stat(dirPath);
          if (now - stats.mtimeMs >= maxAgeMs) {
            await fs.rm(dirPath, { recursive: true, force: true });
            cleanedCount++;
            logger.info({ dirPath }, 'Cleaned orphaned workspace');
          }
        } catch {
          // ignore individual folder errors
        }
      }
    }
  } catch (err) {
    logger.warn({ err }, 'Error during orphaned workspace sweep');
  }

  return cleanedCount;
}
