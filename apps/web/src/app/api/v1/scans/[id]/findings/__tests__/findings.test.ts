import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NextRequest } from 'next/server';
import { GET } from '../route';
import { User } from '@/models/user';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import { createSession } from '@/lib/session';
import * as sessionModule from '@/lib/session';

describe('GET /api/v1/scans/:id/findings', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('returns 401 when not authenticated', async () => {
    vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(undefined);

    const request = new NextRequest('http://localhost:3000/api/v1/scans/507f1f77bcf86cd799439011/findings');
    const response = await GET(request, {
      params: Promise.resolve({ id: '507f1f77bcf86cd799439011' }),
    });

    expect(response.status).toBe(401);
    const body = await response.json();
    expect(body.error.code).toBe('UNAUTHORIZED');
  });

  it('returns 400 for invalid scan ID format', async () => {
    const user = await User.create({
      githubId: '1001',
      username: 'user1',
    });
    const sessionId = await createSession(user._id.toString(), 'token123');
    vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(sessionId);

    const request = new NextRequest('http://localhost:3000/api/v1/scans/invalid-id/findings', {
      headers: {
        cookie: `saferepo_session=${sessionId}`,
      },
    });

    const response = await GET(request, {
      params: Promise.resolve({ id: 'invalid-id' }),
    });

    expect(response.status).toBe(400);
    const body = await response.json();
    expect(body.error.code).toBe('VALIDATION_ERROR');
  });

  it('returns 404 for nonexistent scan', async () => {
    const user = await User.create({
      githubId: '1002',
      username: 'user2',
    });
    const sessionId = await createSession(user._id.toString(), 'token123');
    vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(sessionId);

    const request = new NextRequest('http://localhost:3000/api/v1/scans/507f1f77bcf86cd799439011/findings', {
      headers: {
        cookie: `saferepo_session=${sessionId}`,
      },
    });

    const response = await GET(request, {
      params: Promise.resolve({ id: '507f1f77bcf86cd799439011' }),
    });

    expect(response.status).toBe(404);
    const body = await response.json();
    expect(body.error.code).toBe('NOT_FOUND');
  });

  it('returns 404 when requesting another user\'s scan (cross-tenant isolation)', async () => {
    const userOwner = await User.create({
      githubId: '1003',
      username: 'owner',
    });
    const userOther = await User.create({
      githubId: '1004',
      username: 'other',
    });

    const scan = await Scan.create({
      userId: userOwner._id,
      repositoryOwner: 'owner',
      repositoryName: 'repo',
      repositoryUrl: 'https://github.com/owner/repo',
      branch: 'main',
    });

    // Request with other user's session
    const sessionId = await createSession(userOther._id.toString(), 'tokenOther');
    vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(sessionId);

    const request = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}/findings`, {
      headers: {
        cookie: `saferepo_session=${sessionId}`,
      },
    });

    const response = await GET(request, {
      params: Promise.resolve({ id: scan._id.toString() }),
    });

    expect(response.status).toBe(404);
    const body = await response.json();
    expect(body.error.code).toBe('NOT_FOUND');
  });

  it('returns paginated and filtered findings for authorized scan owner', async () => {
    const user = await User.create({
      githubId: '1005',
      username: 'authorizedUser',
    });

    const scan = await Scan.create({
      userId: user._id,
      repositoryOwner: 'authorizedUser',
      repositoryName: 'project',
      repositoryUrl: 'https://github.com/authorizedUser/project',
      branch: 'main',
      status: 'completed',
    });

    // Create 3 findings: 1 critical, 1 high, 1 medium
    await Finding.create([
      {
        scanId: scan._id,
        userId: user._id,
        scanner: 'semgrep',
        category: 'sast',
        severity: 'critical',
        title: 'Command Injection',
        description: 'exec with user input',
        file: 'src/exec.ts',
        line: 15,
        vulnerabilityId: 'js.exec',
        fingerprint: 'fp-1',
      },
      {
        scanId: scan._id,
        userId: user._id,
        scanner: 'semgrep',
        category: 'sast',
        severity: 'high',
        title: 'SQL Injection',
        description: 'query concatenation',
        file: 'src/db.ts',
        line: 20,
        vulnerabilityId: 'js.sqli',
        fingerprint: 'fp-2',
      },
      {
        scanId: scan._id,
        userId: user._id,
        scanner: 'semgrep',
        category: 'sast',
        severity: 'medium',
        title: 'Weak Crypto',
        description: 'MD5 used',
        file: 'src/hash.ts',
        line: 5,
        vulnerabilityId: 'js.md5',
        fingerprint: 'fp-3',
      },
    ]);

    const sessionId = await createSession(user._id.toString(), 'token123');
    vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(sessionId);

    // 1. Fetch all findings (page 1, per_page 10)
    const req1 = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}/findings?page=1&per_page=10`, {
      headers: {
        cookie: `saferepo_session=${sessionId}`,
      },
    });

    const res1 = await GET(req1, {
      params: Promise.resolve({ id: scan._id.toString() }),
    });

    expect(res1.status).toBe(200);
    const body1 = await res1.json();
    expect(body1.data.length).toBe(3);
    expect(body1.meta.total).toBe(3);
    expect(body1.meta.page).toBe(1);
    expect(body1.meta.pages).toBe(1);

    // 2. Filter by severity=critical
    const req2 = new NextRequest(
      `http://localhost:3000/api/v1/scans/${scan._id}/findings?severity=critical`,
      {
        headers: {
          cookie: `saferepo_session=${sessionId}`,
        },
      }
    );

    const res2 = await GET(req2, {
      params: Promise.resolve({ id: scan._id.toString() }),
    });

    expect(res2.status).toBe(200);
    const body2 = await res2.json();
    expect(body2.data.length).toBe(1);
    expect(body2.data[0].title).toBe('Command Injection');
    expect(body2.data[0].severity).toBe('critical');
    expect(body2.meta.total).toBe(1);

    // 3. Test pagination: page=1&per_page=2
    const req3 = new NextRequest(
      `http://localhost:3000/api/v1/scans/${scan._id}/findings?page=1&per_page=2`,
      {
        headers: {
          cookie: `saferepo_session=${sessionId}`,
        },
      }
    );

    const res3 = await GET(req3, {
      params: Promise.resolve({ id: scan._id.toString() }),
    });

    expect(res3.status).toBe(200);
    const body3 = await res3.json();
    expect(body3.data.length).toBe(2);
    expect(body3.meta.total).toBe(3);
    expect(body3.meta.pages).toBe(2);
  });

  describe('Phase 04 Dependency Findings Integration', () => {
    it('filters findings by category=dependency and category=sast', async () => {
      const user = await User.create({
        githubId: '2001',
        username: 'depUser1',
      });

      const scan = await Scan.create({
        userId: user._id,
        repositoryOwner: 'depUser1',
        repositoryName: 'dep-project',
        repositoryUrl: 'https://github.com/depUser1/dep-project',
        branch: 'main',
        status: 'completed',
      });

      await Finding.create([
        {
          scanId: scan._id,
          userId: user._id,
          scanner: 'semgrep',
          category: 'sast',
          severity: 'high',
          title: 'SAST Finding',
          description: 'SAST desc',
          file: 'src/app.ts',
          line: 10,
          vulnerabilityId: 'sast-rule',
          fingerprint: 'fp-sast-1',
        },
        {
          scanId: scan._id,
          userId: user._id,
          scanner: 'trivy',
          category: 'dependency',
          severity: 'high',
          title: 'CVE-2021-23337 in lodash',
          description: 'Command injection in lodash',
          file: 'package-lock.json',
          line: 0,
          package: 'lodash',
          packageVersion: '4.17.20',
          fixedVersion: '4.17.21',
          vulnerabilityId: 'CVE-2021-23337',
          remediation: 'Upgrade lodash to 4.17.21',
          fingerprint: 'fp-dep-1',
          metadata: { scanners: ['trivy'], ecosystem: 'npm', aliases: ['CVE-2021-23337'] },
        },
        {
          scanId: scan._id,
          userId: user._id,
          scanner: 'osv',
          category: 'dependency',
          severity: 'medium',
          title: 'CVE-2020-28168 in axios',
          description: 'SSRF in axios',
          file: 'package-lock.json',
          line: 0,
          package: 'axios',
          packageVersion: '0.21.1',
          fixedVersion: '0.21.2',
          vulnerabilityId: 'CVE-2020-28168',
          remediation: 'Upgrade axios to 0.21.2',
          fingerprint: 'fp-dep-2',
          metadata: { scanners: ['osv'], ecosystem: 'npm', aliases: ['CVE-2020-28168'] },
        },
      ]);

      const sessionId = await createSession(user._id.toString(), 'tokenDep');
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(sessionId);

      // Query category=dependency
      const reqDep = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scan._id}/findings?category=dependency`,
        {
          headers: { cookie: `saferepo_session=${sessionId}` },
        }
      );

      const resDep = await GET(reqDep, { params: Promise.resolve({ id: scan._id.toString() }) });
      expect(resDep.status).toBe(200);
      const bodyDep = await resDep.json();
      expect(bodyDep.data.length).toBe(2);
      expect(bodyDep.meta.total).toBe(2);
      expect(bodyDep.data.every((f: { category: string }) => f.category === 'dependency')).toBe(true);

      // Query category=sast
      const reqSast = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scan._id}/findings?category=sast`,
        {
          headers: { cookie: `saferepo_session=${sessionId}` },
        }
      );

      const resSast = await GET(reqSast, { params: Promise.resolve({ id: scan._id.toString() }) });
      expect(resSast.status).toBe(200);
      const bodySast = await resSast.json();
      expect(bodySast.data.length).toBe(1);
      expect(bodySast.data[0].category).toBe('sast');
      expect(bodySast.data[0].title).toBe('SAST Finding');
    });

    it('filters findings by scanner=trivy and scanner=osv', async () => {
      const user = await User.create({
        githubId: '2002',
        username: 'depUser2',
      });

      const scan = await Scan.create({
        userId: user._id,
        repositoryOwner: 'depUser2',
        repositoryName: 'scanner-filter-project',
        repositoryUrl: 'https://github.com/depUser2/scanner-filter-project',
        branch: 'main',
        status: 'completed',
      });

      await Finding.create([
        {
          scanId: scan._id,
          userId: user._id,
          scanner: 'trivy',
          category: 'dependency',
          severity: 'high',
          title: 'Trivy Finding',
          description: 'Desc',
          file: 'package-lock.json',
          line: 0,
          package: 'lodash',
          vulnerabilityId: 'CVE-2021-23337',
          fingerprint: 'fp-trivy',
        },
        {
          scanId: scan._id,
          userId: user._id,
          scanner: 'osv',
          category: 'dependency',
          severity: 'critical',
          title: 'OSV Finding',
          description: 'Desc',
          file: 'package-lock.json',
          line: 0,
          package: 'urllib3',
          vulnerabilityId: 'CVE-2023-45803',
          fingerprint: 'fp-osv',
        },
      ]);

      const sessionId = await createSession(user._id.toString(), 'tokenDep2');
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(sessionId);

      // 1. Query scanner=trivy
      const reqTrivy = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scan._id}/findings?scanner=trivy`,
        { headers: { cookie: `saferepo_session=${sessionId}` } }
      );
      const resTrivy = await GET(reqTrivy, { params: Promise.resolve({ id: scan._id.toString() }) });
      expect(resTrivy.status).toBe(200);
      const bodyTrivy = await resTrivy.json();
      expect(bodyTrivy.data.length).toBe(1);
      expect(bodyTrivy.data[0].scanner).toBe('trivy');
      expect(bodyTrivy.data[0].title).toBe('Trivy Finding');

      // 2. Query scanner=osv
      const reqOsv = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scan._id}/findings?scanner=osv`,
        { headers: { cookie: `saferepo_session=${sessionId}` } }
      );
      const resOsv = await GET(reqOsv, { params: Promise.resolve({ id: scan._id.toString() }) });
      expect(resOsv.status).toBe(200);
      const bodyOsv = await resOsv.json();
      expect(bodyOsv.data.length).toBe(1);
      expect(bodyOsv.data[0].scanner).toBe('osv');
      expect(bodyOsv.data[0].title).toBe('OSV Finding');
    });

    it('filters by compound criteria: category=dependency&severity=critical&scanner=osv', async () => {
      const user = await User.create({
        githubId: '2003',
        username: 'depUser3',
      });

      const scan = await Scan.create({
        userId: user._id,
        repositoryOwner: 'depUser3',
        repositoryName: 'compound-project',
        repositoryUrl: 'https://github.com/depUser3/compound-project',
        branch: 'main',
        status: 'completed',
      });

      await Finding.create([
        {
          scanId: scan._id,
          userId: user._id,
          scanner: 'osv',
          category: 'dependency',
          severity: 'critical',
          title: 'Critical OSV Finding',
          description: 'Desc',
          file: 'package-lock.json',
          line: 0,
          package: 'pkg-crit',
          vulnerabilityId: 'CVE-2023-9999',
          fingerprint: 'fp-crit',
        },
        {
          scanId: scan._id,
          userId: user._id,
          scanner: 'osv',
          category: 'dependency',
          severity: 'medium',
          title: 'Medium OSV Finding',
          description: 'Desc',
          file: 'package-lock.json',
          line: 0,
          package: 'pkg-med',
          vulnerabilityId: 'CVE-2023-8888',
          fingerprint: 'fp-med',
        },
        {
          scanId: scan._id,
          userId: user._id,
          scanner: 'trivy',
          category: 'dependency',
          severity: 'critical',
          title: 'Critical Trivy Finding',
          description: 'Desc',
          file: 'package-lock.json',
          line: 0,
          package: 'pkg-triv',
          vulnerabilityId: 'CVE-2023-7777',
          fingerprint: 'fp-triv',
        },
      ]);

      const sessionId = await createSession(user._id.toString(), 'tokenDep3');
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(sessionId);

      const req = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scan._id}/findings?category=dependency&severity=critical&scanner=osv`,
        { headers: { cookie: `saferepo_session=${sessionId}` } }
      );
      const res = await GET(req, { params: Promise.resolve({ id: scan._id.toString() }) });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.length).toBe(1);
      expect(body.data[0].title).toBe('Critical OSV Finding');
      expect(body.data[0].severity).toBe('critical');
      expect(body.data[0].scanner).toBe('osv');
      expect(body.meta.total).toBe(1);
    });

    it('accurately serializes dependency-specific fields and deduplicated metadata in response', async () => {
      const user = await User.create({
        githubId: '2004',
        username: 'depUser4',
      });

      const scan = await Scan.create({
        userId: user._id,
        repositoryOwner: 'depUser4',
        repositoryName: 'serialize-project',
        repositoryUrl: 'https://github.com/depUser4/serialize-project',
        branch: 'main',
        status: 'completed',
      });

      await Finding.create({
        scanId: scan._id,
        userId: user._id,
        scanner: 'trivy',
        category: 'dependency',
        severity: 'critical',
        title: 'CVE-2021-23337 in lodash',
        description: 'Command Injection in lodash template',
        file: 'package-lock.json',
        line: 0,
        package: 'lodash',
        packageVersion: '4.17.20',
        fixedVersion: '4.17.21',
        vulnerabilityId: 'CVE-2021-23337',
        remediation: 'Upgrade lodash to 4.17.21',
        fingerprint: 'dependency:npm:lodash:4.17.20:CVE-2021-23337',
        metadata: {
          scanners: ['osv', 'trivy'],
          ecosystem: 'npm',
          aliases: ['CVE-2021-23337', 'GHSA-35jh-r3h4-6jhm'],
          manifestPaths: ['package-lock.json'],
        },
      });

      const sessionId = await createSession(user._id.toString(), 'tokenDep4');
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(sessionId);

      const req = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scan._id}/findings`,
        { headers: { cookie: `saferepo_session=${sessionId}` } }
      );
      const res = await GET(req, { params: Promise.resolve({ id: scan._id.toString() }) });
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.data.length).toBe(1);

      const item = body.data[0];
      expect(item.package).toBe('lodash');
      expect(item.packageVersion).toBe('4.17.20');
      expect(item.fixedVersion).toBe('4.17.21');
      expect(item.vulnerabilityId).toBe('CVE-2021-23337');
      expect(item.remediation).toBe('Upgrade lodash to 4.17.21');
      expect(item.category).toBe('dependency');
      expect(item.severity).toBe('critical');
      expect(item.metadata?.scanners).toEqual(['osv', 'trivy']);
      expect(item.metadata?.ecosystem).toBe('npm');
      expect(item.metadata?.aliases).toContain('CVE-2021-23337');
      expect(item.metadata?.aliases).toContain('GHSA-35jh-r3h4-6jhm');
    });

    it('rejects invalid category and scanner parameters with 400 VALIDATION_ERROR', async () => {
      const user = await User.create({
        githubId: '2005',
        username: 'depUser5',
      });

      const scan = await Scan.create({
        userId: user._id,
        repositoryOwner: 'depUser5',
        repositoryName: 'validation-project',
        repositoryUrl: 'https://github.com/depUser5/validation-project',
        branch: 'main',
        status: 'completed',
      });

      const sessionId = await createSession(user._id.toString(), 'tokenDep5');
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(sessionId);

      // Invalid category
      const reqBadCat = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scan._id}/findings?category=invalid-category`,
        { headers: { cookie: `saferepo_session=${sessionId}` } }
      );
      const resBadCat = await GET(reqBadCat, { params: Promise.resolve({ id: scan._id.toString() }) });
      expect(resBadCat.status).toBe(400);
      const bodyBadCat = await resBadCat.json();
      expect(bodyBadCat.error.code).toBe('VALIDATION_ERROR');

      // Invalid scanner
      const reqBadScanner = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scan._id}/findings?scanner=unsupported-scanner`,
        { headers: { cookie: `saferepo_session=${sessionId}` } }
      );
      const resBadScanner = await GET(reqBadScanner, { params: Promise.resolve({ id: scan._id.toString() }) });
      expect(resBadScanner.status).toBe(400);
      const bodyBadScanner = await resBadScanner.json();
      expect(bodyBadScanner.error.code).toBe('VALIDATION_ERROR');
    });

    it('Phase 05: queries findings with category=secret and scanner=gitleaks', async () => {
      const user = await User.create({
        githubId: 'secret-api-user',
        username: 'secretUser',
      });

      const scan = await Scan.create({
        userId: user._id,
        repositoryOwner: 'secretUser',
        repositoryName: 'secret-api-repo',
        repositoryUrl: 'https://github.com/secretUser/secret-api-repo',
        branch: 'main',
        status: 'completed',
        scanners: ['semgrep', 'gitleaks'],
      });

      const sessionId = await createSession(user._id.toString(), 'tokenSecretApi');
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(sessionId);

      // Create a secret finding and a sast finding
      await Finding.create([
        {
          scanId: scan._id,
          userId: user._id,
          scanner: 'gitleaks',
          category: 'secret',
          severity: 'critical',
          title: 'Secret detected: AWS Access Key ID',
          description: 'AWS Access Key ID detected in source code.',
          file: 'src/config.ts',
          line: 14,
          column: 1,
          codeSnippet: '[REDACTED SECRET]',
          vulnerabilityId: 'aws-access-key-id',
          fingerprint: 'fp-secret-api-test-1',
          metadata: {
            ruleId: 'aws-access-key-id',
            secretType: 'AWS Access Key ID',
            scanners: ['gitleaks'],
          },
        },
        {
          scanId: scan._id,
          userId: user._id,
          scanner: 'semgrep',
          category: 'sast',
          severity: 'high',
          title: 'SQL Injection',
          description: 'SQL injection',
          file: 'src/db.ts',
          line: 20,
          vulnerabilityId: 'sql-i',
          fingerprint: 'fp-sast-api-test-1',
        },
      ]);

      // 1. Filter by category=secret
      const reqCat = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scan._id}/findings?category=secret`,
        { headers: { cookie: `saferepo_session=${sessionId}` } }
      );
      const resCat = await GET(reqCat, { params: Promise.resolve({ id: scan._id.toString() }) });
      expect(resCat.status).toBe(200);
      const bodyCat = await resCat.json();
      expect(bodyCat.data).toHaveLength(1);
      expect(bodyCat.data[0].category).toBe('secret');
      expect(bodyCat.data[0].scanner).toBe('gitleaks');
      expect(bodyCat.data[0].codeSnippet).toBe('[REDACTED SECRET]');

      // 2. Filter by scanner=gitleaks
      const reqScan = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scan._id}/findings?scanner=gitleaks`,
        { headers: { cookie: `saferepo_session=${sessionId}` } }
      );
      const resScan = await GET(reqScan, { params: Promise.resolve({ id: scan._id.toString() }) });
      expect(resScan.status).toBe(200);
      const bodyScan = await resScan.json();
      expect(bodyScan.data).toHaveLength(1);
      expect(bodyScan.data[0].scanner).toBe('gitleaks');
    });
  });
});


