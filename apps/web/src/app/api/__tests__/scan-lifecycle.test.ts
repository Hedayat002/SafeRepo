import { describe, it, expect, beforeEach, vi } from 'vitest';
import { NextRequest } from 'next/server';
import mongoose from 'mongoose';
import { User, type IUser } from '@/models/user';
import { Session, type ISession } from '@/models/session';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import { DELETE as deleteScanHandler } from '@/app/api/v1/scans/[id]/route';
import { POST as cancelScanHandler } from '@/app/api/v1/scans/[id]/cancel/route';
import { GET as healthHandler } from '@/app/api/health/route';
import * as sessionModule from '@/lib/session';
import { _resetStore } from '@/lib/rate-limit';

describe('Phase 08 — Scan Lifecycle APIs & Health Endpoint', () => {
  let user1: IUser;
  let user2: IUser;
  let session1: ISession;

  beforeEach(async () => {
    await User.deleteMany({});
    await Session.deleteMany({});
    await Scan.deleteMany({});
    await Finding.deleteMany({});
    _resetStore();
    vi.restoreAllMocks();

    user1 = await User.create({ githubId: 'lifecycle-user-1', username: 'lifecycleuser1' });
    session1 = await Session.create({
      sessionId: 'lifecycle-sess-1',
      userId: user1._id,
      githubAccessToken: 'token_user_1',
      expiresAt: new Date(Date.now() + 86400000),
    });

    user2 = await User.create({ githubId: 'lifecycle-user-2', username: 'lifecycleuser2' });
    await Session.create({
      sessionId: 'lifecycle-sess-2',
      userId: user2._id,
      githubAccessToken: 'token_user_2',
      expiresAt: new Date(Date.now() + 86400000),
    });

    // Default authenticated as user1
    vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session1.sessionId);
  });

  // ─────────────────────────────────────────────────────────────
  // DELETE /api/v1/scans/:id
  // ─────────────────────────────────────────────────────────────
  describe('DELETE /api/v1/scans/:id', () => {
    it('returns 401 when unauthenticated', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(undefined);

      const request = new NextRequest('http://localhost:3000/api/v1/scans/507f1f77bcf86cd799439011', {
        method: 'DELETE',
      });
      const response = await deleteScanHandler(request, {
        params: Promise.resolve({ id: '507f1f77bcf86cd799439011' }),
      });

      expect(response.status).toBe(401);
      const json = await response.json();
      expect(json.error.code).toBe('UNAUTHORIZED');
    });

    it('returns 400 when scan ID parameter format is invalid', async () => {
      const request = new NextRequest('http://localhost:3000/api/v1/scans/invalid-id', {
        method: 'DELETE',
      });
      const response = await deleteScanHandler(request, {
        params: Promise.resolve({ id: 'invalid-id' }),
      });

      expect(response.status).toBe(400);
      const json = await response.json();
      expect(json.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 404 when scan does not exist', async () => {
      const fakeId = new mongoose.Types.ObjectId().toString();
      const request = new NextRequest(`http://localhost:3000/api/v1/scans/${fakeId}`, {
        method: 'DELETE',
      });
      const response = await deleteScanHandler(request, {
        params: Promise.resolve({ id: fakeId }),
      });

      expect(response.status).toBe(404);
      const json = await response.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });

    it('returns 404 when scan belongs to another user (anti-enumeration)', async () => {
      const otherScan = await Scan.create({
        userId: user2._id,
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        repositoryUrl: 'https://github.com/owner/repo',
        branch: 'main',
        status: 'completed',
        completedAt: new Date(),
      });

      const request = new NextRequest(`http://localhost:3000/api/v1/scans/${otherScan._id}`, {
        method: 'DELETE',
      });
      const response = await deleteScanHandler(request, {
        params: Promise.resolve({ id: otherScan._id.toString() }),
      });

      expect(response.status).toBe(404);
      // Ensure scan was not deleted
      expect(await Scan.findById(otherScan._id)).not.toBeNull();
    });

    it.each(['queued', 'cloning', 'scanning', 'normalizing'] as const)(
      'rejects deletion of in-progress scan with 409 Conflict (status: %s)',
      async (inProgressStatus) => {
        const scan = await Scan.create({
          userId: user1._id,
          repositoryOwner: 'owner',
          repositoryName: 'repo',
          repositoryUrl: 'https://github.com/owner/repo',
          branch: 'main',
          status: inProgressStatus,
        });

        const request = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}`, {
          method: 'DELETE',
        });
        const response = await deleteScanHandler(request, {
          params: Promise.resolve({ id: scan._id.toString() }),
        });

        expect(response.status).toBe(409);
        const json = await response.json();
        expect(json.error.code).toBe('CONFLICT');
        expect(json.error.message).toContain('currently in progress');
        expect(await Scan.findById(scan._id)).not.toBeNull();
      }
    );

    it('deletes completed scan and returns 204 No Content', async () => {
      const scan = await Scan.create({
        userId: user1._id,
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        repositoryUrl: 'https://github.com/owner/repo',
        branch: 'main',
        status: 'completed',
        completedAt: new Date(),
      });

      const request = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}`, {
        method: 'DELETE',
      });
      const response = await deleteScanHandler(request, {
        params: Promise.resolve({ id: scan._id.toString() }),
      });

      expect(response.status).toBe(204);
      expect(await Scan.findById(scan._id)).toBeNull();
    });

    it('deletes failed and timed_out scans successfully', async () => {
      const failedScan = await Scan.create({
        userId: user1._id,
        repositoryOwner: 'owner',
        repositoryName: 'fail-repo',
        repositoryUrl: 'https://github.com/owner/fail-repo',
        branch: 'main',
        status: 'failed',
        completedAt: new Date(),
      });
      const timedOutScan = await Scan.create({
        userId: user1._id,
        repositoryOwner: 'owner',
        repositoryName: 'timeout-repo',
        repositoryUrl: 'https://github.com/owner/timeout-repo',
        branch: 'main',
        status: 'timed_out',
        completedAt: new Date(),
      });

      const req1 = new NextRequest(`http://localhost:3000/api/v1/scans/${failedScan._id}`, { method: 'DELETE' });
      const res1 = await deleteScanHandler(req1, { params: Promise.resolve({ id: failedScan._id.toString() }) });
      expect(res1.status).toBe(204);
      expect(await Scan.findById(failedScan._id)).toBeNull();

      const req2 = new NextRequest(`http://localhost:3000/api/v1/scans/${timedOutScan._id}`, { method: 'DELETE' });
      const res2 = await deleteScanHandler(req2, { params: Promise.resolve({ id: timedOutScan._id.toString() }) });
      expect(res2.status).toBe(204);
      expect(await Scan.findById(timedOutScan._id)).toBeNull();
    });

    it('cascades deletion to all findings associated with the scan', async () => {
      const scan = await Scan.create({
        userId: user1._id,
        repositoryOwner: 'owner',
        repositoryName: 'cascade-repo',
        repositoryUrl: 'https://github.com/owner/cascade-repo',
        branch: 'main',
        status: 'completed',
        completedAt: new Date(),
      });

      await Finding.create([
        {
          scanId: scan._id,
          userId: user1._id,
          scanner: 'semgrep',
          category: 'sast',
          severity: 'critical',
          title: 'Vuln 1',
          description: 'Desc 1',
          file: 'a.js',
          line: 1,
          fingerprint: 'fp-1',
        },
        {
          scanId: scan._id,
          userId: user1._id,
          scanner: 'trivy',
          category: 'dependency',
          severity: 'high',
          title: 'Vuln 2',
          description: 'Desc 2',
          file: 'b.js',
          line: 2,
          fingerprint: 'fp-2',
        },
      ]);

      expect(await Finding.countDocuments({ scanId: scan._id })).toBe(2);

      const request = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}`, {
        method: 'DELETE',
      });
      const response = await deleteScanHandler(request, {
        params: Promise.resolve({ id: scan._id.toString() }),
      });

      expect(response.status).toBe(204);
      expect(await Scan.findById(scan._id)).toBeNull();
      expect(await Finding.countDocuments({ scanId: scan._id })).toBe(0);
    });

    it('enforces rate limit of 10 deletions per minute per user', async () => {
      // Create 11 scans
      const scans = [];
      for (let i = 0; i < 11; i++) {
        const s = await Scan.create({
          userId: user1._id,
          repositoryOwner: 'owner',
          repositoryName: `rl-${i}`,
          repositoryUrl: `https://github.com/owner/rl-${i}`,
          branch: 'main',
          status: 'completed',
          completedAt: new Date(),
        });
        scans.push(s);
      }

      // First 10 deletions should succeed (204)
      for (let i = 0; i < 10; i++) {
        const req = new NextRequest(`http://localhost:3000/api/v1/scans/${scans[i]._id}`, { method: 'DELETE' });
        const res = await deleteScanHandler(req, { params: Promise.resolve({ id: scans[i]._id.toString() }) });
        expect(res.status).toBe(204);
      }

      // 11th deletion should fail with 429 Too Many Requests
      const req11 = new NextRequest(`http://localhost:3000/api/v1/scans/${scans[10]._id}`, { method: 'DELETE' });
      const res11 = await deleteScanHandler(req11, { params: Promise.resolve({ id: scans[10]._id.toString() }) });

      expect(res11.status).toBe(429);
      const json11 = await res11.json();
      expect(json11.error.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(res11.headers.get('Retry-After')).toBeDefined();
    });
  });

  // ─────────────────────────────────────────────────────────────
  // POST /api/v1/scans/:id/cancel
  // ─────────────────────────────────────────────────────────────
  describe('POST /api/v1/scans/:id/cancel', () => {
    it('returns 401 when unauthenticated', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(undefined);

      const request = new NextRequest('http://localhost:3000/api/v1/scans/507f1f77bcf86cd799439011/cancel', {
        method: 'POST',
      });
      const response = await cancelScanHandler(request, {
        params: Promise.resolve({ id: '507f1f77bcf86cd799439011' }),
      });

      expect(response.status).toBe(401);
      const json = await response.json();
      expect(json.error.code).toBe('UNAUTHORIZED');
    });

    it('returns 400 when scan ID parameter is invalid format', async () => {
      const request = new NextRequest('http://localhost:3000/api/v1/scans/not-an-id/cancel', {
        method: 'POST',
      });
      const response = await cancelScanHandler(request, {
        params: Promise.resolve({ id: 'not-an-id' }),
      });

      expect(response.status).toBe(400);
      const json = await response.json();
      expect(json.error.code).toBe('VALIDATION_ERROR');
    });

    it('returns 404 when scan does not exist', async () => {
      const fakeId = new mongoose.Types.ObjectId().toString();
      const request = new NextRequest(`http://localhost:3000/api/v1/scans/${fakeId}/cancel`, {
        method: 'POST',
      });
      const response = await cancelScanHandler(request, {
        params: Promise.resolve({ id: fakeId }),
      });

      expect(response.status).toBe(404);
      const json = await response.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });

    it('returns 404 when scan belongs to another user (anti-enumeration)', async () => {
      const otherScan = await Scan.create({
        userId: user2._id,
        repositoryOwner: 'owner',
        repositoryName: 'other-repo',
        repositoryUrl: 'https://github.com/owner/other-repo',
        branch: 'main',
        status: 'queued',
      });

      const request = new NextRequest(`http://localhost:3000/api/v1/scans/${otherScan._id}/cancel`, {
        method: 'POST',
      });
      const response = await cancelScanHandler(request, {
        params: Promise.resolve({ id: otherScan._id.toString() }),
      });

      expect(response.status).toBe(404);
      const unchanged = await Scan.findById(otherScan._id);
      expect(unchanged?.status).toBe('queued');
    });

    it('cancels queued scan immediately and transitions to failed', async () => {
      const scan = await Scan.create({
        userId: user1._id,
        repositoryOwner: 'owner',
        repositoryName: 'queued-app',
        repositoryUrl: 'https://github.com/owner/queued-app',
        branch: 'main',
        status: 'queued',
      });

      const request = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}/cancel`, {
        method: 'POST',
      });
      const response = await cancelScanHandler(request, {
        params: Promise.resolve({ id: scan._id.toString() }),
      });

      expect(response.status).toBe(200);
      const json = await response.json();
      expect(json.data.status).toBe('failed');
      expect(json.data.error).toBe('Cancelled by user');
      expect(json.data.completedAt).not.toBeNull();

      const refreshed = await Scan.findById(scan._id);
      expect(refreshed?.status).toBe('failed');
      expect(refreshed?.error).toBe('Cancelled by user');
    });

    it.each(['cloning', 'scanning', 'normalizing'] as const)(
      'sets cancelRequested: true for in-progress scan (status: %s)',
      async (activeStatus) => {
        const scan = await Scan.create({
          userId: user1._id,
          repositoryOwner: 'owner',
          repositoryName: `app-${activeStatus}`,
          repositoryUrl: `https://github.com/owner/app-${activeStatus}`,
          branch: 'main',
          status: activeStatus,
          workerId: 'active-worker-1',
          cancelRequested: false,
        });

        const request = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}/cancel`, {
          method: 'POST',
        });
        const response = await cancelScanHandler(request, {
          params: Promise.resolve({ id: scan._id.toString() }),
        });

        expect(response.status).toBe(200);
        const json = await response.json();
        expect(json.data.cancelRequested).toBe(true);
        expect(json.data.status).toBe(activeStatus);

        const refreshed = await Scan.findById(scan._id);
        expect(refreshed?.cancelRequested).toBe(true);
      }
    );

    it.each(['completed', 'failed', 'timed_out'] as const)(
      'returns 409 Conflict when scan is already in terminal state (%s)',
      async (terminalStatus) => {
        const scan = await Scan.create({
          userId: user1._id,
          repositoryOwner: 'owner',
          repositoryName: `app-${terminalStatus}`,
          repositoryUrl: `https://github.com/owner/app-${terminalStatus}`,
          branch: 'main',
          status: terminalStatus,
          completedAt: new Date(),
        });

        const request = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}/cancel`, {
          method: 'POST',
        });
        const response = await cancelScanHandler(request, {
          params: Promise.resolve({ id: scan._id.toString() }),
        });

        expect(response.status).toBe(409);
        const json = await response.json();
        expect(json.error.code).toBe('CONFLICT');
        expect(json.error.message).toContain('already reached a terminal state');
      }
    );
  });

  // ─────────────────────────────────────────────────────────────
  // GET /api/health (Extended)
  // ─────────────────────────────────────────────────────────────
  describe('GET /api/health (Extended Phase 08)', () => {
    it('returns status ok, db connected, version, queue.pending, and uptime', async () => {
      const response = await healthHandler();
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.status).toBe('ok');
      expect(json.db).toBe('connected');
      expect(json.version).toBe('0.1.0');
      expect(json.queue).toBeDefined();
      expect(json.queue.pending).toBe(0);
      expect(typeof json.uptime).toBe('number');
      expect(json.uptime).toBeGreaterThanOrEqual(0);
      expect(json.timestamp).toBeDefined();
    });

    it('correctly reports pending queue depth', async () => {
      // Create 3 queued scans and 2 completed scans
      for (let i = 0; i < 3; i++) {
        await Scan.create({
          userId: user1._id,
          repositoryOwner: 'owner',
          repositoryName: `pending-${i}`,
          repositoryUrl: `https://github.com/owner/pending-${i}`,
          branch: 'main',
          status: 'queued',
        });
      }
      for (let i = 0; i < 2; i++) {
        await Scan.create({
          userId: user1._id,
          repositoryOwner: 'owner',
          repositoryName: `done-${i}`,
          repositoryUrl: `https://github.com/owner/done-${i}`,
          branch: 'main',
          status: 'completed',
          completedAt: new Date(),
        });
      }

      const response = await healthHandler();
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.queue.pending).toBe(3);
    });
  });
});
