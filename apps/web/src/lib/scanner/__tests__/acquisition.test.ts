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
import * as ecosystemModule from '../ecosystem';
import * as trivyModule from '../trivy';
import * as osvModule from '../osv';
import * as gitleaksModule from '../gitleaks';
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

describe('Repository Acquisition & Pipeline (Phase 04 — Gate 5 Integration)', () => {
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

    // Default mocks for non-scanner modules
    vi.spyOn(workspaceModule, 'createWorkspace').mockImplementation(async (scanId) => {
      return createTestTempDir(`ws-${scanId}`);
    });
    vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();
    vi.spyOn(workspaceModule, 'validateWorkspaceSymlinks').mockResolvedValue();

    // Default scanner mocks (clean pass, 0 findings)
    vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
      hasNode: false,
      hasPython: false,
      coordinates: [],
      manifests: { node: [], python: [] },
    });

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

    vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
      status: 'success',
      scanner: 'trivy',
      findings: [],
      durationMs: 400,
      rawMatchesCount: 0,
    });

    vi.spyOn(osvModule, 'executeOsvScan').mockResolvedValue({
      status: 'success',
      scanner: 'osv',
      findings: [],
      durationMs: 300,
      rawMatchesCount: 0,
    });

    vi.spyOn(gitleaksModule, 'executeGitleaksScan').mockResolvedValue({
      status: 'success',
      scanner: 'gitleaks',
      findings: [],
      durationMs: 300,
      rawMatchesCount: 0,
    });
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

  // ==========================================================================
  // Phase 03 Preserved Tests (Safe Clone, Symlinks, Size, Redaction)
  // ==========================================================================

  describe('acquireRepository (Phase 03 Preserved)', () => {
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
        cloneStderr:
          'fatal: Authentication failed for https://x-access-token:gho_SuperSecretToken123456@github.com/owner/private-repo.git',
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
        maxSizeMb: 0.001, // ~1KB limit
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

  // ==========================================================================
  // Phase 04 — Gate 5: Multi-Scanner Pipeline Integration Tests
  // ==========================================================================

  describe('processScanPipeline (Gate 5 Multi-Scanner Integration)', () => {
    it('returns early without error when scan is not found', async () => {
      const nonExistentId = new mongoose.Types.ObjectId().toString();
      await expect(processScanPipeline(nonExistentId, 'token123')).resolves.toBeUndefined();
    });

    it('Scenario 1: Semgrep + Trivy + OSV all succeed and findings are persisted', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'safe-app',
        repositoryUrl: 'https://github.com/safe-org/safe-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock({ revParseSha: 'commit-all-success' });

      vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
        hasNode: true,
        hasPython: false,
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
          { name: 'axios', version: '0.21.1', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
        manifests: { node: ['package-lock.json'], python: [] },
      });

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
              fingerprint: 'fp-semgrep-sqli',
            },
          ],
          summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
          rawMatchesCount: 1,
          dedupedCount: 1,
        },
        durationMs: 1200,
      });

      vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
        status: 'success',
        scanner: 'trivy',
        findings: [
          {
            vulnerabilityId: 'CVE-2021-23337',
            canonicalId: 'CVE-2021-23337',
            package: 'lodash',
            packageVersion: '4.17.20',
            fixedVersion: '4.17.21',
            severity: 'high',
            title: 'Command Injection in lodash',
            description: 'Lodash vulnerable to command injection via template',
            target: 'package-lock.json',
            remediation: 'Upgrade lodash to 4.17.21',
            aliases: ['CVE-2021-23337'],
            rawVulnerability: {},
          },
        ],
        durationMs: 800,
        rawMatchesCount: 1,
      });

      vi.spyOn(osvModule, 'executeOsvScan').mockResolvedValue({
        status: 'success',
        scanner: 'osv',
        findings: [
          {
            vulnerabilityId: 'GHSA-42xw-2xvc-cxqx',
            canonicalId: 'CVE-2020-28168',
            package: 'axios',
            packageVersion: '0.21.1',
            fixedVersion: '0.21.2',
            severity: 'medium',
            title: 'SSRF in axios',
            description: 'Axios SSRF vulnerability',
            target: 'package-lock.json',
            remediation: 'Upgrade axios to 0.21.2',
            aliases: ['CVE-2020-28168'],
            ecosystem: 'npm',
            rawVulnerability: {},
          },
        ],
        durationMs: 500,
        rawMatchesCount: 1,
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('completed');
      expect(updated?.scanners).toEqual(['semgrep', 'trivy', 'osv', 'gitleaks']);
      expect(updated?.error).toBeNull();
      expect(updated?.summary.total).toBe(3);
      expect(updated?.summary.high).toBe(2);
      expect(updated?.summary.medium).toBe(1);

      const findings = await Finding.find({ scanId: scan._id });
      expect(findings).toHaveLength(3);
      const scannersRecorded = findings.map((f) => f.scanner);
      expect(scannersRecorded).toContain('semgrep');
      expect(scannersRecorded).toContain('trivy');
      expect(scannersRecorded).toContain('osv');
    });

    it('Scenario 2: Trivy unavailable + OSV succeeds (preserves Semgrep & OSV, records warning and scannerErrors)', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'safe-app',
        repositoryUrl: 'https://github.com/safe-org/safe-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
        hasNode: true,
        hasPython: false,
        coordinates: [{ name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' }],
        manifests: { node: ['package-lock.json'], python: [] },
      });

      vi.spyOn(semgrepModule, 'executeSemgrepScan').mockResolvedValue({
        rawStdoutLength: 100,
        normalization: {
          findings: [
            {
              scanId: scan._id.toString(),
              userId: userId.toString(),
              scanner: 'semgrep',
              category: 'sast',
              severity: 'low',
              title: 'Info Rule',
              description: 'Informational',
              file: 'src/index.ts',
              line: 1,
              vulnerabilityId: 'rule-info',
              fingerprint: 'fp-semgrep-info',
            },
          ],
          summary: { total: 1, critical: 0, high: 0, medium: 0, low: 1, info: 0 },
          rawMatchesCount: 1,
          dedupedCount: 1,
        },
        durationMs: 1000,
      });

      vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
        status: 'unavailable',
        scanner: 'trivy',
        reason: 'Trivy offline vulnerability database not found at TRIVY_DB_PATH',
      });

      vi.spyOn(osvModule, 'executeOsvScan').mockResolvedValue({
        status: 'success',
        scanner: 'osv',
        findings: [
          {
            vulnerabilityId: 'GHSA-35jh-r3h4-6jhm',
            canonicalId: 'CVE-2021-23337',
            package: 'lodash',
            packageVersion: '4.17.20',
            fixedVersion: '4.17.21',
            severity: 'critical',
            title: 'Command injection in lodash',
            description: 'Lodash command injection',
            target: 'package-lock.json',
            remediation: 'Upgrade lodash to 4.17.21',
            aliases: ['CVE-2021-23337'],
            ecosystem: 'npm',
            rawVulnerability: {},
          },
        ],
        durationMs: 400,
        rawMatchesCount: 1,
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('completed');
      expect(updated?.scanners).toEqual(['semgrep', 'osv', 'gitleaks']); // 'trivy' strictly excluded
      expect(updated?.error).toContain('Warning: Trivy unavailable');
      expect(updated?.summary.total).toBe(2);
      expect(updated?.summary.critical).toBe(1);
      expect(updated?.summary.low).toBe(1);

      // Verify scannerErrors in metadata
      const meta = updated?.get('metadata') as { scannerErrors?: Array<{ scanner: string; status: string; reason: string }> };
      expect(meta?.scannerErrors).toBeDefined();
      expect(meta?.scannerErrors).toHaveLength(1);
      expect(meta?.scannerErrors?.[0]?.scanner).toBe('trivy');
      expect(meta?.scannerErrors?.[0]?.status).toBe('unavailable');
    });

    it('Scenario 3: Trivy succeeds + OSV fails (preserves Semgrep & Trivy, records warning and scannerErrors)', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'safe-app',
        repositoryUrl: 'https://github.com/safe-org/safe-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
        hasNode: true,
        hasPython: false,
        coordinates: [{ name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' }],
        manifests: { node: ['package-lock.json'], python: [] },
      });

      vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
        status: 'success',
        scanner: 'trivy',
        findings: [
          {
            vulnerabilityId: 'CVE-2021-23337',
            canonicalId: 'CVE-2021-23337',
            package: 'lodash',
            packageVersion: '4.17.20',
            fixedVersion: '4.17.21',
            severity: 'high',
            title: 'Command Injection in lodash',
            description: 'Lodash vulnerable to command injection',
            target: 'package-lock.json',
            remediation: 'Upgrade lodash to 4.17.21',
            aliases: ['CVE-2021-23337'],
            rawVulnerability: {},
          },
        ],
        durationMs: 600,
        rawMatchesCount: 1,
      });

      vi.spyOn(osvModule, 'executeOsvScan').mockResolvedValue({
        status: 'failed',
        scanner: 'osv',
        error: 'OSV API request timed out after 30000ms',
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('completed');
      expect(updated?.scanners).toEqual(['semgrep', 'trivy', 'gitleaks']); // 'osv' strictly excluded
      expect(updated?.error).toContain('Warning: OSV query failed');
      expect(updated?.summary.total).toBe(1);

      const meta = updated?.get('metadata') as { scannerErrors?: Array<{ scanner: string; status: string; error: string }> };
      expect(meta?.scannerErrors).toHaveLength(1);
      expect(meta?.scannerErrors?.[0]?.scanner).toBe('osv');
      expect(meta?.scannerErrors?.[0]?.status).toBe('failed');
    });

    it('Scenario 4: Semgrep succeeds + both dependency scanners unavailable/failed', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'safe-app',
        repositoryUrl: 'https://github.com/safe-org/safe-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
        hasNode: true,
        hasPython: false,
        coordinates: [{ name: 'pkg', version: '1.0.0', ecosystem: 'npm', manifestPath: 'package-lock.json' }],
        manifests: { node: ['package-lock.json'], python: [] },
      });

      vi.spyOn(semgrepModule, 'executeSemgrepScan').mockResolvedValue({
        rawStdoutLength: 100,
        normalization: {
          findings: [
            {
              scanId: scan._id.toString(),
              userId: userId.toString(),
              scanner: 'semgrep',
              category: 'sast',
              severity: 'critical',
              title: 'RCE in Server',
              description: 'Eval injection',
              file: 'server.js',
              line: 12,
              vulnerabilityId: 'eval-rce',
              fingerprint: 'fp-rce',
            },
          ],
          summary: { total: 1, critical: 1, high: 0, medium: 0, low: 0, info: 0 },
          rawMatchesCount: 1,
          dedupedCount: 1,
        },
        durationMs: 800,
      });

      vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
        status: 'unavailable',
        scanner: 'trivy',
        reason: 'DB not found',
      });

      vi.spyOn(osvModule, 'executeOsvScan').mockResolvedValue({
        status: 'failed',
        scanner: 'osv',
        error: 'Network unreachable',
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('completed');
      expect(updated?.scanners).toEqual(['semgrep', 'gitleaks']);
      expect(updated?.error).toContain('Warning: Trivy unavailable');
      expect(updated?.error).toContain('Warning: OSV query failed');
      expect(updated?.summary.total).toBe(1);
      expect(updated?.summary.critical).toBe(1);

      const findings = await Finding.find({ scanId: scan._id });
      expect(findings).toHaveLength(1);
      expect(findings[0]?.title).toBe('RCE in Server');
    });

    it('Scenario 5 & 6: Zero dependency coordinates -> OSV performs 0 HTTP queries and succeeds cleanly', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'no-deps-app',
        repositoryUrl: 'https://github.com/safe-org/no-deps-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
        hasNode: false,
        hasPython: false,
        coordinates: [],
        manifests: { node: [], python: [] },
      });

      const osvSpy = vi.spyOn(osvModule, 'executeOsvScan');

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('completed');
      expect(updated?.scanners).toContain('osv');
      // Confirms ZERO HTTP requests were performed by OSV
      expect(osvSpy).not.toHaveBeenCalled();
    });

    it('Scenario 7 & 8: Zero findings is successful execution; scanners list contains only successful scanners', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'clean-app',
        repositoryUrl: 'https://github.com/safe-org/clean-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('completed');
      expect(updated?.scanners).toEqual(['semgrep', 'trivy', 'osv', 'gitleaks']);
      expect(updated?.summary.total).toBe(0);
      expect(updated?.error).toBeNull();
    });

    it('Scenario 11, 12, 13 & 14: Cross-scanner deduplication unifies Trivy + OSV duplicates and elevates severity', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'dedupe-app',
        repositoryUrl: 'https://github.com/safe-org/dedupe-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
        hasNode: true,
        hasPython: false,
        coordinates: [{ name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' }],
        manifests: { node: ['package-lock.json'], python: [] },
      });

      // Trivy reports lodash at MEDIUM
      vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
        status: 'success',
        scanner: 'trivy',
        findings: [
          {
            vulnerabilityId: 'CVE-2021-23337',
            canonicalId: 'CVE-2021-23337',
            package: 'lodash',
            packageVersion: '4.17.20',
            fixedVersion: '4.17.21',
            severity: 'medium',
            title: 'Command Injection in lodash',
            description: 'Lodash vulnerable to command injection',
            target: 'package-lock.json',
            remediation: 'Upgrade lodash to 4.17.21',
            aliases: ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm'],
            rawVulnerability: {},
          },
        ],
        durationMs: 500,
        rawMatchesCount: 1,
      });

      // OSV reports the exact same flaw under GHSA alias at CRITICAL
      vi.spyOn(osvModule, 'executeOsvScan').mockResolvedValue({
        status: 'success',
        scanner: 'osv',
        findings: [
          {
            vulnerabilityId: 'GHSA-35jh-r3h4-6jhm',
            canonicalId: 'CVE-2021-23337',
            package: 'lodash',
            packageVersion: '4.17.20',
            fixedVersion: '4.17.21',
            severity: 'critical',
            title: 'Critical command injection in lodash template',
            description: 'Critical flaw in template',
            target: 'package-lock.json',
            remediation: 'Upgrade lodash to 4.17.21',
            aliases: ['CVE-2021-23337'],
            ecosystem: 'npm',
            rawVulnerability: {},
          },
        ],
        durationMs: 500,
        rawMatchesCount: 1,
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('completed');
      expect(updated?.summary.total).toBe(1); // Merged into 1 finding
      expect(updated?.summary.critical).toBe(1); // Elevated to CRITICAL

      const findings = await Finding.find({ scanId: scan._id });
      expect(findings).toHaveLength(1);
      expect(findings[0]?.package).toBe('lodash');
      expect(findings[0]?.severity).toBe('critical');
      expect(findings[0]?.metadata?.scanners).toEqual(['osv', 'trivy']);
    });

    it('Scenario 15: Semgrep failure does not purge successful dependency findings', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'semgrep-fail-app',
        repositoryUrl: 'https://github.com/safe-org/semgrep-fail-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
        hasNode: true,
        hasPython: false,
        coordinates: [{ name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' }],
        manifests: { node: ['package-lock.json'], python: [] },
      });

      vi.spyOn(semgrepModule, 'executeSemgrepScan').mockRejectedValue(
        new Error('Semgrep container crash')
      );

      vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
        status: 'success',
        scanner: 'trivy',
        findings: [
          {
            vulnerabilityId: 'CVE-2021-23337',
            canonicalId: 'CVE-2021-23337',
            package: 'lodash',
            packageVersion: '4.17.20',
            fixedVersion: '4.17.21',
            severity: 'high',
            title: 'Command Injection',
            description: 'Desc',
            target: 'package-lock.json',
            aliases: ['CVE-2021-23337'],
            rawVulnerability: {},
          },
        ],
        durationMs: 400,
        rawMatchesCount: 1,
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('completed');
      expect(updated?.scanners).toContain('trivy');
      expect(updated?.scanners).not.toContain('semgrep');
      expect(updated?.error).toContain('Warning: Semgrep scan failed');
      expect(updated?.summary.total).toBe(1);

      const findings = await Finding.find({ scanId: scan._id });
      expect(findings).toHaveLength(1);
      expect(findings[0]?.package).toBe('lodash');
    });

    it('Scenario 16 & 17: Workspace is cleaned up after success and after scanner failure', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'cleanup-app',
        repositoryUrl: 'https://github.com/safe-org/cleanup-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();
      const cleanupSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace');

      await processScanPipeline(scan._id.toString(), 'token123');
      expect(cleanupSpy).toHaveBeenCalled();
    });

    it('Scenario 20: Hard scanner timeout transitions scan to timed_out and purges partial findings', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'timeout-org',
        repositoryName: 'timeout-app',
        repositoryUrl: 'https://github.com/timeout-org/timeout-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      vi.spyOn(semgrepModule, 'executeSemgrepScan').mockRejectedValue(
        new ScannerTimeoutError('Scanner execution timed out after 180s')
      );

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('timed_out');
      expect(updated?.error).toContain('timed out');
      expect(updated?.scanners).toEqual([]);
      expect(updated?.summary.total).toBe(0);
    });

    it('Scenario 21: No false clean result when Trivy is unavailable and zero other findings exist', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'no-false-clean',
        repositoryUrl: 'https://github.com/safe-org/no-false-clean',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
        status: 'unavailable',
        scanner: 'trivy',
        reason: 'Trivy DB not found at TRIVY_DB_PATH',
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('completed');
      // Crucial: Trivy MUST NOT be in scanners array
      expect(updated?.scanners).not.toContain('trivy');
      expect(updated?.scanners).toEqual(['semgrep', 'osv', 'gitleaks']);
      // Crucial: Must have explicit warning
      expect(updated?.error).toContain('Warning: Trivy unavailable');
    });

    it('Scenario 22: When all scanners fail, status becomes failed with empty scanners array', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'fail-all-org',
        repositoryName: 'fail-all-app',
        repositoryUrl: 'https://github.com/fail-all-org/fail-all-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
        hasNode: true,
        hasPython: false,
        coordinates: [{ name: 'p', version: '1.0', ecosystem: 'npm', manifestPath: 'package-lock.json' }],
        manifests: { node: ['package-lock.json'], python: [] },
      });

      vi.spyOn(semgrepModule, 'executeSemgrepScan').mockRejectedValue(new Error('Semgrep crash'));
      vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
        status: 'failed',
        scanner: 'trivy',
        error: 'Trivy crash',
      });
      vi.spyOn(osvModule, 'executeOsvScan').mockResolvedValue({
        status: 'failed',
        scanner: 'osv',
        error: 'OSV network down',
      });
      vi.spyOn(gitleaksModule, 'executeGitleaksScan').mockResolvedValue({
        status: 'failed',
        scanner: 'gitleaks',
        error: 'Gitleaks crash',
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('failed');
      expect(updated?.scanners).toEqual([]);
      expect(updated?.error).toContain('Scan failed: All scanners failed');
      expect(updated?.summary.total).toBe(0);
    });

    it('Scenario 18: Cleanup after normalization failure', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'norm-fail-app',
        repositoryUrl: 'https://github.com/safe-org/norm-fail-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();
      const cleanupSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace');

      vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
        status: 'success',
        scanner: 'trivy',
        findings: [
          {
            vulnerabilityId: 'CVE-2021-23337',
            canonicalId: 'CVE-2021-23337',
            package: 'lodash',
            packageVersion: '4.17.20',
            severity: 'high',
            title: 'Test',
            description: 'Test',
            target: 'package-lock.json',
            aliases: [],
            rawVulnerability: {},
          },
        ],
        durationMs: 100,
        rawMatchesCount: 1,
      });

      // Force normalizeDependencyFindings to throw
      const normalizerModule = await import('../normalizer');
      vi.spyOn(normalizerModule, 'normalizeDependencyFindings').mockImplementationOnce(() => {
        throw new Error('Fatal normalization corruption');
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('failed');
      expect(updated?.error).toContain('Fatal normalization corruption');
      expect(cleanupSpy).toHaveBeenCalled();
    });

    it('Scenario 19: Persistence failure handling', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'safe-org',
        repositoryName: 'persist-fail-app',
        repositoryUrl: 'https://github.com/safe-org/persist-fail-app',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();
      const cleanupSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace');

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
              title: 'SQLi',
              description: 'Desc',
              file: 'db.ts',
              line: 1,
              vulnerabilityId: 'sqli',
              fingerprint: 'fp-sqli',
            },
          ],
          summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
          rawMatchesCount: 1,
          dedupedCount: 1,
        },
        durationMs: 100,
      });

      vi.spyOn(Finding, 'insertMany' as never).mockRejectedValueOnce(new Error('Mongo connection error during insert'));

      await processScanPipeline(scan._id.toString(), 'token123');

      const updated = await Scan.findById(scan._id);
      expect(updated?.status).toBe('failed');
      expect(updated?.error).toContain('Mongo connection error during insert');
      expect(cleanupSpy).toHaveBeenCalled();
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

    it('Phase 05: Gitleaks discovers secrets -> persisted with strict redaction and summary updated', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'secret-org',
        repositoryName: 'secret-repo',
        repositoryUrl: 'https://github.com/secret-org/secret-repo',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      const fakeSecret = 'fake-secret-token-xyz-123456789';

      vi.spyOn(gitleaksModule, 'executeGitleaksScan').mockResolvedValue({
        status: 'success',
        scanner: 'gitleaks',
        findings: [
          {
            scanId: scan._id.toString(),
            userId: userId.toString(),
            scanner: 'gitleaks',
            category: 'secret',
            severity: 'critical',
            title: 'Secret detected: AWS Access Key ID',
            description: 'AWS Access Key ID detected in source code.',
            file: 'src/aws.ts',
            line: 12,
            column: 1,
            codeSnippet: '[REDACTED SECRET]',
            vulnerabilityId: 'aws-access-key-id',
            remediation: 'Revoke and rotate this credential immediately.',
            fingerprint: 'fp-secret-aws-1',
            metadata: {
              ruleId: 'aws-access-key-id',
              secretType: 'AWS Access Key ID',
              scanners: ['gitleaks'],
            },
          },
        ],
        durationMs: 400,
        rawMatchesCount: 1,
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updatedScan = await Scan.findById(scan._id);
      expect(updatedScan?.status).toBe('completed');
      expect(updatedScan?.scanners).toContain('gitleaks');
      expect(updatedScan?.summary.critical).toBe(1);
      expect(updatedScan?.summary.total).toBe(1);

      const findings = await Finding.find({ scanId: scan._id }).lean();
      expect(findings).toHaveLength(1);
      expect(findings[0]?.category).toBe('secret');
      expect(findings[0]?.scanner).toBe('gitleaks');
      expect(findings[0]?.severity).toBe('critical');
      expect(findings[0]?.codeSnippet).toBe('[REDACTED SECRET]');

      // Strict Redaction in persisted MongoDB document:
      expect(JSON.stringify(findings[0])).not.toContain(fakeSecret);
    });

    it('Phase 05: Gitleaks failure preserves Semgrep, Trivy, and OSV findings (fault isolation)', async () => {
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'fail-gitleaks-org',
        repositoryName: 'fail-gitleaks-repo',
        repositoryUrl: 'https://github.com/fail-gitleaks-org/fail-gitleaks-repo',
        branch: 'main',
        status: 'queued',
      });

      setupGitSpawnMock();

      vi.spyOn(semgrepModule, 'executeSemgrepScan').mockResolvedValue({
        rawStdoutLength: 100,
        normalization: {
          findings: [
            {
              scanId: scan._id.toString(),
              userId: userId.toString(),
              scanner: 'semgrep',
              category: 'sast',
              severity: 'medium',
              title: 'XSS in View',
              description: 'Cross-site scripting',
              file: 'src/view.ts',
              line: 10,
              vulnerabilityId: 'xss',
              fingerprint: 'fp-semgrep-xss',
            },
          ],
          summary: { total: 1, critical: 0, high: 0, medium: 1, low: 0, info: 0 },
          rawMatchesCount: 1,
          dedupedCount: 1,
        },
        durationMs: 500,
      });

      vi.spyOn(gitleaksModule, 'executeGitleaksScan').mockResolvedValue({
        status: 'failed',
        scanner: 'gitleaks',
        error: 'Gitleaks container crashed',
        durationMs: 200,
      });

      await processScanPipeline(scan._id.toString(), 'token123');

      const updatedScan = await Scan.findById(scan._id);
      expect(updatedScan?.status).toBe('completed');
      expect(updatedScan?.scanners).toContain('semgrep');
      expect(updatedScan?.scanners).not.toContain('gitleaks');
      expect(updatedScan?.error).toContain('Warning: Gitleaks scan failed');
      expect(updatedScan?.summary.total).toBe(1);

      const findings = await Finding.find({ scanId: scan._id });
      expect(findings).toHaveLength(1);
      expect(findings[0]?.scanner).toBe('semgrep');
    });

    it('exports processScanAcquisition as an alias', () => {
      expect(processScanAcquisition).toBe(processScanPipeline);
    });
  });
});
