import { describe, it, expect, afterEach } from 'vitest';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import {
  createWorkspace,
  cleanupWorkspace,
  validateWorkspaceSymlinks,
  cleanupOrphanedWorkspaces,
} from '@/lib/scanner/workspace';

describe('Workspace Manager', () => {
  const testScanId = `test-scan-${Date.now()}`;
  let createdPath: string | null = null;

  afterEach(async () => {
    if (createdPath) {
      await cleanupWorkspace(createdPath);
      createdPath = null;
    }
  });

  it('should create an isolated workspace directory', async () => {
    createdPath = await createWorkspace(testScanId);
    expect(createdPath).toBeDefined();

    const stats = await fs.stat(createdPath);
    expect(stats.isDirectory()).toBe(true);
  });

  it('should clean up the workspace directory safely', async () => {
    createdPath = await createWorkspace(testScanId);
    await cleanupWorkspace(createdPath);

    await expect(fs.access(createdPath)).rejects.toThrow();
    createdPath = null;
  });

  it('should pass symlink validation when symlinks resolve within workspace', async () => {
    createdPath = await createWorkspace(testScanId);

    const targetFile = path.join(createdPath, 'target.txt');
    await fs.writeFile(targetFile, 'hello safe content');

    const linkPath = path.join(createdPath, 'symlink.txt');
    try {
      await fs.symlink('target.txt', linkPath);
      await expect(validateWorkspaceSymlinks(createdPath)).resolves.not.toThrow();
    } catch (e: unknown) {
      // Windows unprivileged symlink creation may throw EPERM; if so, test is skipped gracefully
      if ((e as { code?: string }).code === 'EPERM') return;
      throw e;
    }
  });

  it('should detect malicious symlink escape and throw an error', async () => {
    createdPath = await createWorkspace(testScanId);

    // External target outside the workspace
    const externalTarget = os.tmpdir();
    const maliciousLink = path.join(createdPath, 'escape-link');

    try {
      await fs.symlink(externalTarget, maliciousLink, 'dir');
      await expect(validateWorkspaceSymlinks(createdPath)).rejects.toThrow(
        /Malicious symlink escape detected/
      );
    } catch (e: unknown) {
      if ((e as { code?: string }).code === 'EPERM') return;
      throw e;
    }
  });

  it('should cleanup orphaned workspaces older than max age', async () => {
    const orphanId = `orphan-${Date.now()}`;
    const orphanPath = await createWorkspace(orphanId);

    // Call cleanup with maxAgeMs = 0 (immediately expired)
    const cleaned = await cleanupOrphanedWorkspaces(0);
    expect(cleaned).toBeGreaterThanOrEqual(1);

    await expect(fs.access(orphanPath)).rejects.toThrow();
  });
});
