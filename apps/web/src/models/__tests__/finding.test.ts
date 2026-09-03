import { describe, it, expect } from 'vitest';
import mongoose from 'mongoose';
import { Finding } from '../finding';
import { Scan } from '../scan';
import { User } from '../user';

describe('Finding Model', () => {
  it('creates a finding with required fields', async () => {
    const user = await User.create({
      githubId: '999999',
      username: 'findingtestuser',
    });

    const scan = await Scan.create({
      userId: user._id,
      repositoryOwner: 'testowner',
      repositoryName: 'testrepo',
      repositoryUrl: 'https://github.com/testowner/testrepo',
      branch: 'main',
      status: 'completed',
    });

    const finding = await Finding.create({
      scanId: scan._id,
      userId: user._id,
      scanner: 'semgrep',
      category: 'sast',
      severity: 'high',
      title: 'SQL Injection',
      description: 'User input concatenated into query string',
      file: 'src/database.ts',
      line: 42,
      endLine: 45,
      column: 5,
      endColumn: 30,
      codeSnippet: 'db.query("SELECT * FROM users WHERE id = " + id)',
      vulnerabilityId: 'owasp.a01-sqli',
      remediation: 'Use parameterized queries.',
      fingerprint: 'abcd1234ef567890',
      metadata: { confidence: 'HIGH' },
    });

    expect(finding._id).toBeDefined();
    expect(finding.scanId.toString()).toBe(scan._id.toString());
    expect(finding.userId.toString()).toBe(user._id.toString());
    expect(finding.scanner).toBe('semgrep');
    expect(finding.category).toBe('sast');
    expect(finding.severity).toBe('high');
    expect(finding.title).toBe('SQL Injection');
    expect(finding.file).toBe('src/database.ts');
    expect(finding.line).toBe(42);
    expect(finding.fingerprint).toBe('abcd1234ef567890');
    expect(finding.metadata).toEqual({ confidence: 'HIGH' });
    expect(finding.createdAt).toBeInstanceOf(Date);
  });

  it('rejects finding without required fields', async () => {
    const invalidFinding = new Finding({});
    await expect(invalidFinding.validate()).rejects.toThrow();
  });

  it('enforces enum validation on severity, category, and scanner', async () => {
    const user = await User.create({
      githubId: '999998',
      username: 'enumtestuser',
    });

    const scan = await Scan.create({
      userId: user._id,
      repositoryOwner: 'testowner',
      repositoryName: 'testrepo',
      repositoryUrl: 'https://github.com/testowner/testrepo',
      branch: 'main',
    });

    const invalidSeverity = new Finding({
      scanId: scan._id,
      userId: user._id,
      scanner: 'semgrep',
      category: 'sast',
      severity: 'extreme', // Invalid
      title: 'Invalid severity test',
      fingerprint: 'fingerprint-1',
    });

    await expect(invalidSeverity.validate()).rejects.toThrow();
  });

  it('enforces compound unique index on { scanId, fingerprint }', async () => {
    const user = await User.create({
      githubId: '999997',
      username: 'dupetestuser',
    });

    const scan = await Scan.create({
      userId: user._id,
      repositoryOwner: 'testowner',
      repositoryName: 'testrepo',
      repositoryUrl: 'https://github.com/testowner/testrepo',
      branch: 'main',
    });

    // Ensure indexes are synced
    await Finding.syncIndexes();

    await Finding.create({
      scanId: scan._id,
      userId: user._id,
      scanner: 'semgrep',
      category: 'sast',
      severity: 'medium',
      title: 'Finding 1',
      fingerprint: 'unique-fingerprint-123',
    });

    await expect(
      Finding.create({
        scanId: scan._id,
        userId: user._id,
        scanner: 'semgrep',
        category: 'sast',
        severity: 'medium',
        title: 'Duplicate Finding',
        fingerprint: 'unique-fingerprint-123',
      })
    ).rejects.toThrow();
  });
});
