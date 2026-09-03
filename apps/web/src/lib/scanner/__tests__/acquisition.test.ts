import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { EventEmitter } from 'events';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import mongoose from 'mongoose';

vi.mock('child_process', () => ({
  spawn: vi.fn(),
}));

import { Readable } from 'stream';
import { spawn, type ChildProcess } from 'child_process';
import { User } from '@/models/user';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import {
  acquireRepository,
  processScanPipeline,
  processScanAcquisition,
} from '../acquisition';
import * as workspaceModule from '../workspace';
import * as semgrepModule from '../semgrep';
import { ScannerTimeoutError } from '../runner';

const mockSpawn = vi.mocked(spawn);

interface MockSpawnOptions {
  cloneExitCode?: number;
  cloneStderr?: string;
  cloneError?: Error;
  revParseSha?: string;
}

function setupGitSpawnMock(options: MockSpawnOptions = {}) {
  const {
    cloneExitCode = 0,
    cloneStderr = '',
    cloneError,
    revParseSha = 'c0ffee1234567890abcdef',
  } = options;

  mockSpawn.mockImplementation((_cmd, args) => {
    const stdout = new Readable({ read() {} });
    const stderr = new Readable({ read() {} });
    const proc = Object.assign(new EventEmitter(), {
      stdout,
      stderr,
      stdin: null,
      stdio: [null, stdout, stderr, null, null],
      killed: false,
      pid: 12345,
      kill: vi.fn(),
      send: vi.fn(),
      disconnect: vi.fn(),
      unref: vi.fn(),
      ref: vi.fn(),
      exitCode: null,
      signalCode: null,
      spawnargs: [],
      spawnfile: '',
      connected: false,
    }) as unknown as ChildProcess;

    const argList = (args as string[]) || [];

    process.nextTick(() => {
      if (argList.includes('clone')) {
        if (cloneError) {
          proc.emit('error', cloneError);
        } else if (cloneExitCode !== 0) {
          stderr.emit('data', Buffer.from(cloneStderr));
          proc.emit('close', cloneExitCode);
        } else {
          proc.emit('close', 0);
        }
      } else if (argList.includes('rev-parse')) {
        stdout.emit('data', Buffer.from(`${revParseSha}\n`));
        proc.emit('close', 0);
      } else {
        proc.emit('close', 0);
      }
    });

    return proc;
  });
}

describe('Repository Acquisition & Pipeline (Phase 03)', () => {
  let userId: mongoose.Types.ObjectId;
  const tempDirsToClean: string[] = [];

  async function createTestTempDir(prefix: string): Promise<string> {
    const dir = path.join(os.tmpdir(), `${prefix}-${Date.now()}-${Math.random().toString(36).substring(7)}`);
    await fs.mkdir(dir, { recursive: true });
    tempDirsToClean.push(dir);
    return dir;
  }

  beforeEach(async () => {
    vi.restoreAllMocks();
    await User.deleteMany({});
    await Scan.deleteMany({});
    await Finding.deleteMany({});

    const user = await User.create({
      githubId: 'acq-user-1',
      username: 'acq-user',
    });
    userId = user._id;
  });

  afterEach(async () => {
    vi.restoreAllMocks();
    for (const dir of tempDirsToClean) {
      try {
        await fs.rm(dir, { recursive: true, force: true });
      } catch {
        // ignore
      }
    }
    tempDirsToClean.length = 0;
  });

  describe('acquireRepository', () => {
    it('successfully clones, calculates size, checks symlinks, and returns commit SHA', async () => {
      const mockWorkspace = await createTestTempDir('test-acq-ws');
      await fs.writeFile(path.join(mockWorkspace, 'README.md'), 'test repository content');

      vi.spyOn(workspaceModule, 'createWorkspace').mockResolvedValue(mockWorkspace);
      vi.spyOn(workspaceModule, 'validateWorkspaceSymlinks').mockResolvedValue();
      const cleanupSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

      setupGitSpawnMock({ revParseSha: 'c0ffee1234567890abcdef' });

      const result = await acquireRepository({
        scanId: 'scan-123',
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        branch: 'main',
        accessToken: 'gho_token123',
        maxSizeMb: 50,
      });

      expect(result.workspacePath).toBe(mockWorkspace);
      expect(result.commitSha).toBe('c0ffee1234567890abcdef');
      expect(result.sizeBytes).toBeGreaterThan(0);
      expect(cleanupSpy).not.toHaveBeenCalled();
    });

    it('redacts access tokens from git error messages on failure', async () => {
      const mockWorkspace = await createTestTempDir('test-acq-fail');
      vi.spyOn(workspaceModule, 'createWorkspace').mockResolvedValue(mockWorkspace);
      const cleanupSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

      setupGitSpawnMock({
        cloneExitCode: 128,
        cloneStderr: 'fatal: Authentication failed for https://x-access-token:gho_SuperSecretToken123456@github.com/owner/private-repo.git',
      });

      const acquirePromise = acquireRepository({
        scanId: 'scan-fail-token',
        repositoryOwner: 'owner',
        repositoryName: 'private-repo',
        branch: 'main',
        accessToken: 'gho_SuperSecretToken123456',
      });

      await expect(acquirePromise).rejects.toThrow(/\[REDACTED\]/);
      await expect(acquirePromise).rejects.not.toThrow(/gho_SuperSecretToken123456/);
      expect(cleanupSpy).toHaveBeenCalledWith(mockWorkspace);
    });

    it('cleans up workspace and rejects on git process spawn error', async () => {
      const mockWorkspace = await createTestTempDir('test-acq-err');
      vi.spyOn(workspaceModule, 'createWorkspace').mockResolvedValue(mockWorkspace);
      const cleanupSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

      setupGitSpawnMock({ cloneError: new Error('spawn git ENOENT') });

      const acquirePromise = acquireRepository({
        scanId: 'scan-spawn-err',
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        branch: 'main',
        accessToken: 'gho_token',
      });

      await expect(acquirePromise).rejects.toThrow('spawn git ENOENT');
      expect(cleanupSpy).toHaveBeenCalledWith(mockWorkspace);
    });

    it('throws error and cleans up when repository size exceeds limit', async () => {
      const mockWorkspace = await createTestTempDir('test-acq-oversize');
      await fs.writeFile(path.join(mockWorkspace, 'large.dat'), Buffer.alloc(2048, 'a'));

      vi.spyOn(workspaceModule, 'createWorkspace').mockResolvedValue(mockWorkspace);
      const cleanupSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

      setupGitSpawnMock({ revParseSha: 'sha123' });

      const acquirePromise = acquireRepository({
        scanId: 'scan-oversize',
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        branch: 'main',
        accessToken: 'gho_token',
        maxSizeMb: 0.001, // ~1KB limit so 2KB exceeds
      });

      await expect(acquirePromise).rejects.toThrow(/exceeds limit/);
      expect(cleanupSpy).toHaveBeenCalledWith(mockWorkspace);
    });

    it('throws and cleans up when symlink validation fails', async () => {
      const mockWorkspace = await createTestTempDir('test-acq-symlink');

      vi.spyOn(workspaceModule, 'createWorkspace').mockResolvedValue(mockWorkspace);
      vi.spyOn(workspaceModule, 'validateWorkspaceSymlinks').mockRejectedValue(
        new Error('Malicious symlink escape detected')
      );
      const cleanupSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

      setupGitSpawnMock({ revParseSha: 'sha123' });

      const acquirePromise = acquireRepository({
        scanId: 'scan-symlink-fail',
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        branch: 'main',
        accessToken: 'gho_token',
      });

      await expect(acquirePromise).rejects.toThrow('Malicious symlink escape detected');
      expect(cleanupSpy).toHaveBeenCalledWith(mockWorkspace);
    });
  });

  describe('processScanPipeline', () => {
    it('returns early without error when scan is not found', async () => {
      const nonExistentId = new mongoose.Types.ObjectId().toString();
      await expect(processScanPipeline(nonExistentId, 'token123')).resolves.toBeUndefined();
    });

    it('runs end-to-end pipeline: cloning -> scanning -> normalizing -> completed with findings', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'safe-app',
        repositoryUrl: 'https://github.com/safe-org/safe-app',
        branch: 'main',
        status: 'queued',
      });

      const mockWorkspace = await createTestTempDir('saferepo-test-ws');
      await fs.writeFile(path.join(mockWorkspace, 'index.js'), '// test');

      vi.spyOn(workspaceModule, 'createWorkspace').mockResolvedValue(mockWorkspace);
      vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();
      vi.spyOn(workspaceModule, 'validateWorkspaceSymlinks').mockResolvedValue();

      setupGitSpawnMock({ revParseSha: 'commit-sha-999' });

      // Mock Semgrep scanner execution returning normalized findings
      vi.spyOn(semgrepModule, 'executeSemgrepScan').mockResolvedValue({
        rawStdoutLength: 100,
        normalization: {
          findings: [
            {
              scanId: scan._id.toString(),
              userId: userId.toString(),
              scanner: 'semgrep',
              category: 'sast',
              severity: 'high',
              title: 'SQL Injection',
              description: 'Untrusted input in query',
              file: 'src/db.ts',
              line: 42,
              vulnerabilityId: 'sql-injection',
              fingerprint: 'fp-sql-1',
            },
            {
              scanId: scan._id.toString(),
              userId: userId.toString(),
              scanner: 'semgrep',
              category: 'sast',
              severity: 'critical',
              title: 'Remote Code Execution',
              description: 'Insecure eval',
              file: 'src/eval.ts',
              line: 10,
              vulnerabilityId: 'rce-eval',
              fingerprint: 'fp-rce-1',
            },
          ],
          summary: {
            total: 2,
            critical: 1,
            high: 1,
            medium: 0,
            low: 0,
            info: 0,
          },
          rawMatchesCount: 2,
          dedupedCount: 2,
        },
        durationMs: 2500,
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      // Verify updated scan in DB
      const updatedScan = await Scan.findById(scan._id);
      expect(updatedScan?.status).toBe('completed');
      expect(updatedScan?.commitSha).toBe('commit-sha-999');
      expect(updatedScan?.summary.total).toBe(2);
      expect(updatedScan?.summary.critical).toBe(1);
      expect(updatedScan?.summary.high).toBe(1);
      expect(updatedScan?.completedAt).toBeDefined();
      expect(updatedScan?.workspacePath).toBeNull(); // Cleaned up in finally

      // Verify findings persisted in DB
      const findings = await Finding.find({ scanId: scan._id });
      expect(findings).toHaveLength(2);
      expect(findings.map((f) => f.title)).toContain('SQL Injection');
      expect(findings.map((f) => f.title)).toContain('Remote Code Execution');
    });

    it('handles batch insertion when findings exceed 500 items', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'large-org',
        repositoryName: 'large-app',
        repositoryUrl: 'https://github.com/large-org/large-app',
        branch: 'main',
        status: 'queued',
      });

      const mockWorkspace = await createTestTempDir('saferepo-test-ws-large');
      await fs.writeFile(path.join(mockWorkspace, 'large.js'), '// test');

      vi.spyOn(workspaceModule, 'createWorkspace').mockResolvedValue(mockWorkspace);
      vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();
      vi.spyOn(workspaceModule, 'validateWorkspaceSymlinks').mockResolvedValue();

      setupGitSpawnMock({ revParseSha: 'sha-large' });

      // Create 550 dummy findings to trigger chunking logic (500 + 50)
      const mockFindings = Array.from({ length: 550 }, (_, i) => ({
        scanId: scan._id.toString(),
        userId: userId.toString(),
        scanner: 'semgrep' as const,
        category: 'sast' as const,
        severity: 'low' as const,
        title: `Finding #${i}`,
        description: 'Batch test description',
        file: `src/file_${i}.ts`,
        line: i + 1,
        vulnerabilityId: `rule-${i}`,
        fingerprint: `fp-batch-${i}`,
      }));

      vi.spyOn(semgrepModule, 'executeSemgrepScan').mockResolvedValue({
        rawStdoutLength: 100,
        normalization: {
          findings: mockFindings,
          summary: {
            total: 550,
            critical: 0,
            high: 0,
            medium: 0,
            low: 550,
            info: 0,
          },
          rawMatchesCount: 550,
          dedupedCount: 550,
        },
        durationMs: 3000,
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updatedScan = await Scan.findById(scan._id);
      expect(updatedScan?.status).toBe('completed');
      expect(updatedScan?.summary.total).toBe(550);

      const count = await Finding.countDocuments({ scanId: scan._id });
      expect(count).toBe(550);
    });

    it('handles scanner timeout: sets status to timed_out and purges partial findings', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'timeout-org',
        repositoryName: 'timeout-app',
        repositoryUrl: 'https://github.com/timeout-org/timeout-app',
        branch: 'main',
        status: 'queued',
      });

      const mockWorkspace = await createTestTempDir('saferepo-timeout-ws');
      await fs.writeFile(path.join(mockWorkspace, 'code.js'), '// test');

      vi.spyOn(workspaceModule, 'createWorkspace').mockResolvedValue(mockWorkspace);
      vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();
      vi.spyOn(workspaceModule, 'validateWorkspaceSymlinks').mockResolvedValue();

      setupGitSpawnMock({ revParseSha: 'sha-timeout' });

      // Pre-insert a stale partial finding
      await Finding.create({
        scanId: scan._id,
        userId,
        scanner: 'semgrep',
        category: 'sast',
        severity: 'info',
        title: 'Partial Finding',
        fingerprint: 'fp-partial',
      });

      vi.spyOn(semgrepModule, 'executeSemgrepScan').mockRejectedValue(
        new ScannerTimeoutError('Scanner execution timed out after 120s')
      );

      await processScanPipeline(scan._id.toString(), 'token123');

      const updatedScan = await Scan.findById(scan._id);
      expect(updatedScan?.status).toBe('timed_out');
      expect(updatedScan?.error).toContain('timed out');
      expect(updatedScan?.summary.total).toBe(0);

      // Verify partial findings were purged
      const findingsCount = await Finding.countDocuments({ scanId: scan._id });
      expect(findingsCount).toBe(0);
    });

    it('handles acquisition failure: sets status to failed and cleans up', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'fail-org',
        repositoryName: 'fail-app',
        repositoryUrl: 'https://github.com/fail-org/fail-app',
        branch: 'main',
        status: 'queued',
      });

      const mockWorkspace = await createTestTempDir('saferepo-fail-ws');
      vi.spyOn(workspaceModule, 'createWorkspace').mockResolvedValue(mockWorkspace);
      const cleanupSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

      setupGitSpawnMock({
        cloneExitCode: 128,
        cloneStderr: 'fatal: remote repository not found',
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updatedScan = await Scan.findById(scan._id);
      expect(updatedScan?.status).toBe('failed');
      expect(updatedScan?.error).toContain('remote repository not found');
      expect(cleanupSpy).toHaveBeenCalled();
    });

    it('safely handles cleanupWorkspace throwing an error in finally', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'finally-org',
        repositoryName: 'finally-app',
        repositoryUrl: 'https://github.com/finally-org/finally-app',
        branch: 'main',
        status: 'queued',
      });

      const mockWorkspace = await createTestTempDir('saferepo-finally-ws');
      await fs.writeFile(path.join(mockWorkspace, 'code.js'), '// test');

      vi.spyOn(workspaceModule, 'createWorkspace').mockResolvedValue(mockWorkspace);
      vi.spyOn(workspaceModule, 'validateWorkspaceSymlinks').mockResolvedValue();
      vi.spyOn(workspaceModule, 'cleanupWorkspace').mockRejectedValue(new Error('EBUSY: resource busy'));

      setupGitSpawnMock({ revParseSha: 'sha-fin' });

      vi.spyOn(semgrepModule, 'executeSemgrepScan').mockResolvedValue({
        rawStdoutLength: 100,
        normalization: {
          findings: [],
          summary: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 },
          rawMatchesCount: 0,
          dedupedCount: 0,
        },
        durationMs: 500,
      });

      // Should not throw unhandled error
      await expect(
        processScanPipeline(scan._id.toString(), 'token123')
      ).resolves.toBeUndefined();
    });

    it('exports processScanAcquisition as an alias', () => {
      expect(processScanAcquisition).toBe(processScanPipeline);
    });
  });
});
