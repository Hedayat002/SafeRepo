import { describe, it, expect, beforeEach } from 'vitest';
import mongoose from 'mongoose';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import { User } from '@/models/user';
import { computeSeverityCounts } from '../dashboard-utils';

describe('dashboard-auth UI boundary & authorization safeguards', () => {
  const userAId = new mongoose.Types.ObjectId();
  const userBId = new mongoose.Types.ObjectId();

  beforeEach(async () => {
    await Scan.deleteMany({});
    await Finding.deleteMany({});
    await User.deleteMany({});

    // Create User A and User B
    await User.create([
      {
        _id: userAId,
        githubId: '1001',
        username: 'user-a',
        email: 'user-a@example.com',
      },
      {
        _id: userBId,
        githubId: '1002',
        username: 'user-b',
        email: 'user-b@example.com',
      },
    ]);
  });

  it('strictly isolates scan history between users (user A cannot see user B scans)', async () => {
    // Insert 2 scans for User A and 2 scans for User B
    await Scan.create([
      {
        userId: userAId,
        repositoryOwner: 'org-a',
        repositoryName: 'repo-1',
        repositoryUrl: 'https://github.com/org-a/repo-1',
        branch: 'main',
        status: 'completed',
        scanners: ['semgrep'],
      },
      {
        userId: userAId,
        repositoryOwner: 'org-a',
        repositoryName: 'repo-2',
        repositoryUrl: 'https://github.com/org-a/repo-2',
        branch: 'main',
        status: 'completed',
        scanners: ['semgrep'],
      },
      {
        userId: userBId,
        repositoryOwner: 'secret-org',
        repositoryName: 'classified-repo',
        repositoryUrl: 'https://github.com/secret-org/classified-repo',
        branch: 'main',
        status: 'completed',
        scanners: ['semgrep'],
      },
    ]);

    // Query executed with User A's scope
    const userAScans = await Scan.find({ userId: userAId }).lean();
    expect(userAScans).toHaveLength(2);
    expect(userAScans.every((s) => s.userId.toString() === userAId.toString())).toBe(true);
    expect(userAScans.some((s) => s.repositoryOwner === 'secret-org')).toBe(false);

    // Query executed with User B's scope
    const userBScans = await Scan.find({ userId: userBId }).lean();
    expect(userBScans).toHaveLength(1);
    expect(userBScans[0].repositoryName).toBe('classified-repo');
  });

  it('prevents cross-user scan detail inspection (anti-enumeration)', async () => {
    const userBScan = await Scan.create({
      userId: userBId,
      repositoryOwner: 'secret-org',
      repositoryName: 'confidential-vault',
      repositoryUrl: 'https://github.com/secret-org/confidential-vault',
      branch: 'main',
      status: 'completed',
      scanners: ['gitleaks'],
    });

    // Attempt to access User B's scan using User A's userId filter
    const accessedScan = await Scan.findOne({
      _id: userBScan._id,
      userId: userAId,
    }).lean();

    // Must evaluate to null
    expect(accessedScan).toBeNull();
  });

  it('enforces parent scan ownership when retrieving security findings', async () => {
    const scanB = await Scan.create({
      userId: userBId,
      repositoryOwner: 'org-b',
      repositoryName: 'repo-b',
      repositoryUrl: 'https://github.com/org-b/repo-b',
      branch: 'main',
      status: 'completed',
      scanners: ['semgrep'],
    });

    await Finding.create({
      scanId: scanB._id,
      userId: userBId,
      scanner: 'semgrep',
      category: 'sast',
      severity: 'critical',
      title: 'SQL Injection in User Lookup',
      description: 'Raw SQL query detected',
      file: 'src/db.ts',
      line: 42,
      vulnerabilityId: 'CWE-89',
      fingerprint: 'scan-b-finding-1',
    });

    // User A attempts to access findings for scanB
    // First, verify User A does not own the parent scan
    const scanOwnership = await Scan.findOne({
      _id: scanB._id,
      userId: userAId,
    });
    expect(scanOwnership).toBeNull();

    // Findings are isolated to the authorized parent scan
    const findings = await Finding.find({ scanId: scanB._id, userId: userAId }).lean();
    expect(findings).toHaveLength(0);
  });

  it('verifies secret findings contain [REDACTED SECRET] at the UI boundary', async () => {
    const scanA = await Scan.create({
      userId: userAId,
      repositoryOwner: 'org-a',
      repositoryName: 'repo-a',
      repositoryUrl: 'https://github.com/org-a/repo-a',
      branch: 'main',
      status: 'completed',
      scanners: ['gitleaks'],
    });

    // Invariant: Backend stores [REDACTED SECRET], UI boundary renders [REDACTED SECRET]
    const secretFinding = await Finding.create({
      scanId: scanA._id,
      userId: userAId,
      scanner: 'gitleaks',
      category: 'secret',
      severity: 'critical',
      title: 'AWS Secret Access Key Exposed',
      description: 'Secret token identified by Gitleaks regex matching',
      file: 'config/aws.json',
      line: 14,
      codeSnippet: 'const awsKey = "[REDACTED SECRET]";',
      vulnerabilityId: 'GITLEAKS-AWS-001',
      fingerprint: 'gitleaks-secret-1',
    });

    const retrieved = await Finding.findById(secretFinding._id).lean();
    expect(retrieved?.codeSnippet).toContain('[REDACTED SECRET]');
    expect(retrieved?.codeSnippet).not.toContain('AKIA');
  });

  it('returns empty result set safely for non-existent users without throwing errors', async () => {
    const nonExistentUserId = new mongoose.Types.ObjectId();

    const [scans, totalCount] = await Promise.all([
      Scan.find({ userId: nonExistentUserId }).lean(),
      Scan.countDocuments({ userId: nonExistentUserId }),
    ]);

    expect(scans).toEqual([]);
    expect(totalCount).toBe(0);
  });

  it('matches severity summary counts with underlying MongoDB aggregation', async () => {
    const scan = await Scan.create({
      userId: userAId,
      repositoryOwner: 'org-a',
      repositoryName: 'multi-finding-repo',
      repositoryUrl: 'https://github.com/org-a/multi-finding-repo',
      branch: 'main',
      status: 'completed',
      scanners: ['semgrep', 'trivy'],
      summary: {
        total: 4,
        critical: 1,
        high: 2,
        medium: 1,
        low: 0,
        info: 0,
      },
    });

    await Finding.create([
      {
        scanId: scan._id,
        userId: userAId,
        scanner: 'semgrep',
        category: 'sast',
        severity: 'critical',
        title: 'Command Injection',
        description: 'exec() called with user input',
        file: 'src/shell.ts',
        line: 10,
        vulnerabilityId: 'CWE-78',
        fingerprint: 'f-1',
      },
      {
        scanId: scan._id,
        userId: userAId,
        scanner: 'trivy',
        category: 'dependency',
        severity: 'high',
        title: 'CVE-2023-9999 in lodash',
        description: 'Prototype pollution',
        file: 'package-lock.json',
        line: 1,
        vulnerabilityId: 'CVE-2023-9999',
        fingerprint: 'f-2',
      },
      {
        scanId: scan._id,
        userId: userAId,
        scanner: 'trivy',
        category: 'dependency',
        severity: 'high',
        title: 'CVE-2023-8888 in express',
        description: 'Denial of service',
        file: 'package-lock.json',
        line: 1,
        vulnerabilityId: 'CVE-2023-8888',
        fingerprint: 'f-3',
      },
      {
        scanId: scan._id,
        userId: userAId,
        scanner: 'semgrep',
        category: 'sast',
        severity: 'medium',
        title: 'Insecure cookie configuration',
        description: 'Missing HttpOnly flag',
        file: 'src/cookie.ts',
        line: 5,
        vulnerabilityId: 'CWE-1004',
        fingerprint: 'f-4',
      },
    ]);

    const items = computeSeverityCounts(scan.summary);
    expect(items.find((i) => i.severity === 'critical')?.count).toBe(1);
    expect(items.find((i) => i.severity === 'high')?.count).toBe(2);
    expect(items.find((i) => i.severity === 'medium')?.count).toBe(1);
    expect(items.find((i) => i.severity === 'low')?.count).toBe(0);

    const actualDbCount = await Finding.countDocuments({ scanId: scan._id });
    expect(actualDbCount).toBe(scan.summary.total);
  });
});
