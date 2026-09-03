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
});
