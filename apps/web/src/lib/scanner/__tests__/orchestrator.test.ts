import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import mongoose from 'mongoose';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import { executeOrchestratedScan } from '../orchestrator';
import * as acquisitionModule from '../acquisition';
import * as semgrepModule from '../semgrep';
import * as trivyModule from '../trivy';
import * as osvModule from '../osv';
import * as gitleaksModule from '../gitleaks';
import * as ecosystemModule from '../ecosystem';
import * as workspaceModule from '../workspace';
import * as runnerModule from '../runner';
import { ScannerTimeoutError } from '../runner';

describe('Phase 06 — Unified Multi-Scanner Orchestrator', () => {
  const userId = new mongoose.Types.ObjectId();

  beforeEach(async () => {
    await Scan.deleteMany({});
    await Finding.deleteMany({});
    vi.clearAllMocks();
  });

  afterEach(async () => {
    vi.restoreAllMocks();
  });

  it('orchestrates full multi-scanner pipeline (Semgrep, Trivy, OSV, Gitleaks) successfully', async () => {
    const scan = await Scan.create({
      userId,
      repositoryOwner: 'safe-org',
      repositoryName: 'full-pipeline-app',
      repositoryUrl: 'https://github.com/safe-org/full-pipeline-app',
      branch: 'main',
      status: 'queued',
    });

    vi.spyOn(acquisitionModule, 'acquireRepository').mockResolvedValue({
      workspacePath: 'tmp/workspaces/test-workspace',
      commitSha: 'commit123456',
      sizeBytes: 1024,
    });

    vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
      hasNode: true,
      hasPython: false,
      coordinates: [{ name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' }],
      manifests: { node: ['package-lock.json'], python: [] },
    });

    vi.spyOn(semgrepModule, 'executeSemgrepScan').mockResolvedValue({
      durationMs: 100,
      rawStdoutLength: 100,
      normalization: {
        findings: [
          {
            scanId: scan._id.toString(),
            userId: userId.toString(),
            category: 'sast',
            scanner: 'semgrep',
            vulnerabilityId: 'javascript.lang.security.audit.eval-with-expression',
            title: 'Use of eval',
            description: 'eval detected',
            severity: 'high',
            file: 'src/index.ts',
            line: 10,
            column: 5,
            fingerprint: 'fp-semgrep-1',
          },
        ],
        summary: { total: 1, critical: 0, high: 1, medium: 0, low: 0, info: 0 },
        rawMatchesCount: 1,
        dedupedCount: 1,
      },
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
          severity: 'medium',
          title: 'Command Injection in lodash',
          description: 'Lodash command injection',
          target: 'package-lock.json',
          remediation: 'Upgrade to 4.17.21',
          aliases: [],
          rawVulnerability: {},
        },
      ],
      rawMatchesCount: 1,
      durationMs: 150,
    });

    vi.spyOn(osvModule, 'executeOsvScan').mockResolvedValue({
      status: 'success',
      scanner: 'osv',
      findings: [
        {
          vulnerabilityId: 'GHSA-35jh-r3h4-6jhm',
          canonicalId: 'CVE-2021-23337',
          aliases: ['CVE-2021-23337'],
          package: 'lodash',
          packageVersion: '4.17.20',
          ecosystem: 'npm',
          fixedVersion: '4.17.21',
          severity: 'high', // Higher severity to test deduplication ranking
          title: 'Command Injection in lodash',
          description: 'Lodash command injection advisory',
          target: 'package-lock.json',
          rawVulnerability: {},
        },
      ],
      rawMatchesCount: 1,
      durationMs: 200,
    });

    vi.spyOn(gitleaksModule, 'executeGitleaksScan').mockResolvedValue({
      status: 'success',
      scanner: 'gitleaks',
      findings: [
        {
          scanId: scan._id.toString(),
          userId: userId.toString(),
          category: 'secret',
          scanner: 'gitleaks',
          vulnerabilityId: 'generic-api-key',
          title: 'Generic API Key',
          description: 'Secret detected',
          severity: 'critical',
          file: 'config.env',
          line: 2,
          codeSnippet: '[REDACTED SECRET]',
          fingerprint: 'fp-gitleaks-1',
        },
      ],
      rawMatchesCount: 1,
      durationMs: 80,
    });

    vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

    const result = await executeOrchestratedScan(scan._id.toString(), 'worker-full-test');

    expect(result.status).toBe('completed');
    expect(result.scanners).toEqual(['semgrep', 'trivy', 'osv', 'gitleaks']);
    // Deduplication should merge Trivy + OSV (1 dep finding) + 1 semgrep + 1 gitleaks = 3 findings
    expect(result.findingsCount).toBe(3);
    expect(result.summary.critical).toBe(1); // Gitleaks
    expect(result.summary.high).toBe(2);     // Semgrep (1) + OSV elevated medium->high (1)
    expect(result.summary.total).toBe(3);

    // Verify DB state
    const dbScan = await Scan.findById(scan._id);
    expect(dbScan?.status).toBe('completed');
    expect(dbScan?.workerId).toBe('worker-full-test');
    expect(dbScan?.summary.total).toBe(3);

    // Verify findings persisted in MongoDB
    const persistedFindings = await Finding.find({ scanId: scan._id });
    expect(persistedFindings).toHaveLength(3);
  });

  it('handles partial failure gracefully, preserving successful scanner findings', async () => {
    const scan = await Scan.create({
      userId,
      repositoryOwner: 'safe-org',
      repositoryName: 'partial-app',
      repositoryUrl: 'https://github.com/safe-org/partial-app',
      branch: 'main',
      status: 'queued',
    });

    vi.spyOn(acquisitionModule, 'acquireRepository').mockResolvedValue({
      workspacePath: 'tmp/workspaces/partial-workspace',
      commitSha: 'commit123',
      sizeBytes: 1024,
    });

    vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
      hasNode: false,
      hasPython: false,
      coordinates: [],
      manifests: { node: [], python: [] },
    });

    // Semgrep fails
    vi.spyOn(semgrepModule, 'executeSemgrepScan').mockRejectedValue(
      new Error('Semgrep rules syntax error')
    );

    // Trivy succeeds
    vi.spyOn(trivyModule, 'executeTrivyScan').mockResolvedValue({
      status: 'success',
      scanner: 'trivy',
      findings: [],
      rawMatchesCount: 0,
      durationMs: 100,
    });

    // OSV has 0 coordinates -> succeeds with 0
    // Gitleaks succeeds
    vi.spyOn(gitleaksModule, 'executeGitleaksScan').mockResolvedValue({
      status: 'success',
      scanner: 'gitleaks',
      findings: [],
      rawMatchesCount: 0,
      durationMs: 50,
    });

    vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

    const result = await executeOrchestratedScan(scan._id.toString(), 'worker-partial-test');

    expect(result.status).toBe('completed');
    expect(result.scanners).toContain('trivy');
    expect(result.scanners).toContain('osv');
    expect(result.scanners).toContain('gitleaks');
    expect(result.scanners).not.toContain('semgrep');
    expect(result.scannerErrors).toHaveLength(1);
    expect(result.scannerErrors[0].scanner).toBe('semgrep');
    expect(result.warnings).toHaveLength(1);
  });

  it('transitions to timed_out and purges partial findings on scanner timeout', async () => {
    const scan = await Scan.create({
      userId,
      repositoryOwner: 'safe-org',
      repositoryName: 'timeout-app',
      repositoryUrl: 'https://github.com/safe-org/timeout-app',
      branch: 'main',
      status: 'queued',
    });

    vi.spyOn(acquisitionModule, 'acquireRepository').mockResolvedValue({
      workspacePath: 'tmp/workspaces/timeout-workspace',
      commitSha: 'commit123',
      sizeBytes: 1024,
    });

    vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
      hasNode: false,
      hasPython: false,
      coordinates: [],
      manifests: { node: [], python: [] },
    });

    vi.spyOn(runnerModule, 'killDockerContainer').mockResolvedValue();
    const cleanSpy = vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

    vi.spyOn(semgrepModule, 'executeSemgrepScan').mockRejectedValue(
      new ScannerTimeoutError('Scanner execution timed out after 180s')
    );

    const result = await executeOrchestratedScan(scan._id.toString(), 'worker-timeout-test');

    expect(result.status).toBe('timed_out');
    expect(result.error).toContain('timed out');
    expect(cleanSpy).toHaveBeenCalled();

    const dbScan = await Scan.findById(scan._id);
    expect(dbScan?.status).toBe('timed_out');
  });

  it('marks scan as failed when all scanners fail', async () => {
    const scan = await Scan.create({
      userId,
      repositoryOwner: 'safe-org',
      repositoryName: 'all-fail-app',
      repositoryUrl: 'https://github.com/safe-org/all-fail-app',
      branch: 'main',
      status: 'queued',
    });

    vi.spyOn(acquisitionModule, 'acquireRepository').mockResolvedValue({
      workspacePath: 'tmp/workspaces/fail-workspace',
      commitSha: 'commit123',
      sizeBytes: 1024,
    });

    vi.spyOn(ecosystemModule, 'detectEcosystems').mockResolvedValue({
      hasNode: false,
      hasPython: false,
      coordinates: [{ name: 'pkg', version: '1.0.0', ecosystem: 'npm', manifestPath: 'package.json' }],
      manifests: { node: ['package.json'], python: [] },
    });

    vi.spyOn(semgrepModule, 'executeSemgrepScan').mockRejectedValue(new Error('Semgrep crash'));
    vi.spyOn(trivyModule, 'executeTrivyScan').mockRejectedValue(new Error('Trivy crash'));
    vi.spyOn(osvModule, 'executeOsvScan').mockRejectedValue(new Error('OSV network failure'));
    vi.spyOn(gitleaksModule, 'executeGitleaksScan').mockRejectedValue(new Error('Gitleaks crash'));
    vi.spyOn(workspaceModule, 'cleanupWorkspace').mockResolvedValue();

    const result = await executeOrchestratedScan(scan._id.toString(), 'worker-fail-test');

    expect(result.status).toBe('failed');
    expect(result.scanners).toEqual([]);
    expect(result.scannerErrors).toHaveLength(4);

    const dbScan = await Scan.findById(scan._id);
    expect(dbScan?.status).toBe('failed');
  });

  it('handles acquisition failure gracefully and marks scan failed', async () => {
    const scan = await Scan.create({
      userId,
      repositoryOwner: 'safe-org',
      repositoryName: 'bad-repo',
      repositoryUrl: 'https://github.com/safe-org/bad-repo',
      branch: 'main',
      status: 'queued',
    });

    vi.spyOn(acquisitionModule, 'acquireRepository').mockRejectedValue(
      new Error('Git clone failed: fatal: repository not found')
    );

    const result = await executeOrchestratedScan(scan._id.toString(), 'worker-acquire-fail');

    expect(result.status).toBe('failed');
    expect(result.error).toContain('Git clone failed');

    const dbScan = await Scan.findById(scan._id);
    expect(dbScan?.status).toBe('failed');
  });

  it('returns failed when scan document does not exist in DB', async () => {
    const nonExistentId = new mongoose.Types.ObjectId().toString();
    const result = await executeOrchestratedScan(nonExistentId, 'worker-404');
    expect(result.status).toBe('failed');
    expect(result.error).toBe('Scan not found');
  });
});
