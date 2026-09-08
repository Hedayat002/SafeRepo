import { describe, it, expect, beforeEach, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { User, type IUser } from '@/models/user';
import { Session, type ISession } from '@/models/session';
import { Scan } from '@/models/scan';
import { POST as createScanHandler, GET as listScansHandler } from '@/app/api/v1/scans/route';
import { GET as getScanHandler } from '@/app/api/v1/scans/[id]/route';
import * as sessionModule from '@/lib/session';
import * as githubModule from '@/lib/github';
import type { GitHubRepository, ScanResponseData } from '@/types';

describe('Scans API Routes', () => {
  let user1: IUser;
  let user2: IUser;
  let session1: ISession;

  beforeEach(async () => {
    await User.deleteMany({});
    await Session.deleteMany({});
    await Scan.deleteMany({});
    vi.restoreAllMocks();

    user1 = await User.create({ githubId: 'scan-user-1', username: 'scanuser1' });
    session1 = await Session.create({
      sessionId: 'scan-sess-1',
      userId: user1._id,
      githubAccessToken: 'token_user_1',
      expiresAt: new Date(Date.now() + 86400000),
    });

    user2 = await User.create({ githubId: 'scan-user-2', username: 'scanuser2' });
    await Session.create({
      sessionId: 'scan-sess-2',
      userId: user2._id,
      githubAccessToken: 'token_user_2',
      expiresAt: new Date(Date.now() + 86400000),
    });
  });

  describe('POST /api/v1/scans', () => {
    it('should return 401 when unauthenticated', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(undefined);

      const request = new NextRequest('http://localhost:3000/api/v1/scans', {
        method: 'POST',
        body: JSON.stringify({ repositoryOwner: 'org', repositoryName: 'repo' }),
      });

      const response = await createScanHandler(request);
      expect(response.status).toBe(401);
    });

    it('should return 400 when payload is invalid', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session1.sessionId);

      const request = new NextRequest('http://localhost:3000/api/v1/scans', {
        method: 'POST',
        body: JSON.stringify({ repositoryOwner: '' }),
      });

      const response = await createScanHandler(request);
      expect(response.status).toBe(400);

      const json = await response.json();
      expect(json.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return 404 if repository does not exist on GitHub', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session1.sessionId);
      vi.spyOn(githubModule, 'getRepo').mockResolvedValue(null);

      const request = new NextRequest('http://localhost:3000/api/v1/scans', {
        method: 'POST',
        body: JSON.stringify({ repositoryOwner: 'unknown', repositoryName: 'repo' }),
      });

      const response = await createScanHandler(request);
      expect(response.status).toBe(404);
    });

    it('should return 400 if repository exceeds size limit', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session1.sessionId);
      vi.spyOn(githubModule, 'getRepo').mockResolvedValue({
        id: 123,
        name: 'huge-repo',
        full_name: 'org/huge-repo',
        owner: { login: 'org', avatar_url: '' },
        private: false,
        html_url: 'https://github.com/org/huge-repo',
        description: null,
        fork: false,
        language: 'TypeScript',
        default_branch: 'main',
        stargazers_count: 0,
        forks_count: 0,
        open_issues_count: 0,
        created_at: '',
        updated_at: '',
        pushed_at: '',
        // 200MB reported size (204800 KB)
        size: 204800,
      } as unknown as GitHubRepository);

      const request = new NextRequest('http://localhost:3000/api/v1/scans', {
        method: 'POST',
        body: JSON.stringify({ repositoryOwner: 'org', repositoryName: 'huge-repo' }),
      });

      const response = await createScanHandler(request);
      expect(response.status).toBe(400);

      const json = await response.json();
      expect(json.error.message).toMatch(/exceeds maximum allowed size/);
    });

    it('should create scan and return 201 when valid', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session1.sessionId);
      vi.spyOn(githubModule, 'getRepo').mockResolvedValue({
        id: 456,
        name: 'good-repo',
        full_name: 'org/good-repo',
        owner: { login: 'org', avatar_url: '' },
        private: false,
        html_url: 'https://github.com/org/good-repo',
        description: 'valid repo',
        fork: false,
        language: 'TypeScript',
        default_branch: 'main',
        stargazers_count: 5,
        forks_count: 1,
        open_issues_count: 0,
        created_at: '',
        updated_at: '',
        pushed_at: '',
        size: 5000,
      } as unknown as GitHubRepository);

      const request = new NextRequest('http://localhost:3000/api/v1/scans', {
        method: 'POST',
        body: JSON.stringify({ repositoryOwner: 'org', repositoryName: 'good-repo' }),
      });

      const response = await createScanHandler(request);
      expect(response.status).toBe(201);

      const json = await response.json();
      expect(json.data.id).toBeDefined();
      expect(json.data.status).toBe('queued');
      expect(json.data.repositoryName).toBe('good-repo');

      // Verify created in DB with queued status for worker pickup
      const dbScan = await Scan.findById(json.data.id);
      expect(dbScan).not.toBeNull();
      expect(dbScan?.userId.toString()).toBe(user1._id.toString());
      expect(dbScan?.status).toBe('queued');
    });
  });

  describe('GET /api/v1/scans', () => {
    it('should return 401 when unauthenticated', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(undefined);

      const request = new NextRequest('http://localhost:3000/api/v1/scans');
      const response = await listScansHandler(request);
      expect(response.status).toBe(401);
    });

    it('should return scans only for the authenticated user', async () => {
      // User 1 scans
      await Scan.create({
        userId: user1._id,
        repositoryOwner: 'org1',
        repositoryName: 'repo1',
        repositoryUrl: 'https://github.com/org1/repo1',
        branch: 'main',
      });
      await Scan.create({
        userId: user1._id,
        repositoryOwner: 'org1',
        repositoryName: 'repo2',
        repositoryUrl: 'https://github.com/org1/repo2',
        branch: 'main',
      });

      // User 2 scan
      await Scan.create({
        userId: user2._id,
        repositoryOwner: 'org2',
        repositoryName: 'repo3',
        repositoryUrl: 'https://github.com/org2/repo3',
        branch: 'main',
      });

      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session1.sessionId);

      const request = new NextRequest('http://localhost:3000/api/v1/scans');
      const response = await listScansHandler(request);
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.data).toHaveLength(2);
      expect(json.meta.total).toBe(2);
      expect(json.data.every((s: ScanResponseData) => s.repositoryOwner === 'org1')).toBe(true);
    });
  });

  describe('GET /api/v1/scans/:id', () => {
    it('should return 401 when unauthenticated', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(undefined);

      const request = new NextRequest('http://localhost:3000/api/v1/scans/507f1f77bcf86cd799439011');
      const response = await getScanHandler(request, {
        params: Promise.resolve({ id: '507f1f77bcf86cd799439011' }),
      });
      expect(response.status).toBe(401);
    });

    it('should return 404 when scan belongs to another user (anti-enumeration)', async () => {
      const scanUser2 = await Scan.create({
        userId: user2._id,
        repositoryOwner: 'org2',
        repositoryName: 'private-repo',
        repositoryUrl: 'https://github.com/org2/private-repo',
        branch: 'main',
      });

      // User 1 tries to access User 2's scan
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session1.sessionId);

      const request = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scanUser2._id.toString()}`
      );
      const response = await getScanHandler(request, {
        params: Promise.resolve({ id: scanUser2._id.toString() }),
      });
      expect(response.status).toBe(404);
    });

    it('should return scan details when authenticated and owner', async () => {
      const scanUser1 = await Scan.create({
        userId: user1._id,
        repositoryOwner: 'org1',
        repositoryName: 'my-scan-repo',
        repositoryUrl: 'https://github.com/org1/my-scan-repo',
        branch: 'dev',
        status: 'cloning',
        commitSha: 'fedcba654321',
      });

      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session1.sessionId);

      const request = new NextRequest(
        `http://localhost:3000/api/v1/scans/${scanUser1._id.toString()}`
      );
      const response = await getScanHandler(request, {
        params: Promise.resolve({ id: scanUser1._id.toString() }),
      });
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.data.id).toBe(scanUser1._id.toString());
      expect(json.data.status).toBe('cloning');
      expect(json.data.commitSha).toBe('fedcba654321');
      expect(json.data.branch).toBe('dev');
    });
  });
});
