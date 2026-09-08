import { describe, it, expect, beforeEach, vi } from 'vitest';
import { NextRequest, NextResponse } from 'next/server';
import nextConfig from '../../../../next.config.mjs';
import { formatErrorResponse, ValidationError, NotFoundError, ConflictError } from '@/lib/errors';
import { withRequestLogging, redactHeaders, SENSITIVE_HEADERS } from '@/lib/middleware/request-logger';
import { GET as getFindingsHandler } from '@/app/api/v1/scans/[id]/findings/route';
import { DELETE as deleteScanHandler } from '@/app/api/v1/scans/[id]/route';
import { POST as cancelScanHandler } from '@/app/api/v1/scans/[id]/cancel/route';
import { User, type IUser } from '@/models/user';
import { Session, type ISession } from '@/models/session';
import { Scan } from '@/models/scan';
import * as sessionModule from '@/lib/session';
import { _resetStore } from '@/lib/rate-limit';

describe('Phase 08 — Security Hardening Tests', () => {
  let user1: IUser;
  let user2: IUser;
  let session1: ISession;

  beforeEach(async () => {
    await User.deleteMany({});
    await Session.deleteMany({});
    await Scan.deleteMany({});
    _resetStore();
    vi.restoreAllMocks();

    user1 = await User.create({ githubId: 'sec-user-1', username: 'secuser1' });
    session1 = await Session.create({
      sessionId: 'sec-sess-1',
      userId: user1._id,
      githubAccessToken: 'token_user_1',
      expiresAt: new Date(Date.now() + 86400000),
    });

    user2 = await User.create({ githubId: 'sec-user-2', username: 'secuser2' });
    await Session.create({
      sessionId: 'sec-sess-2',
      userId: user2._id,
      githubAccessToken: 'token_user_2',
      expiresAt: new Date(Date.now() + 86400000),
    });

    vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session1.sessionId);
  });

  // ─────────────────────────────────────────────────────────────
  // 1. Content-Security-Policy & Security Headers
  // ─────────────────────────────────────────────────────────────
  describe('Security Headers & CSP Configuration', () => {
    it('defines Content-Security-Policy in nextConfig headers', async () => {
      expect(nextConfig.headers).toBeDefined();
      const headersConfig = await nextConfig.headers!();
      const allHeaders = headersConfig.flatMap((h: { headers: Array<{ key: string; value: string }> }) => h.headers);

      const csp = allHeaders.find((h: { key: string }) => h.key === 'Content-Security-Policy');
      expect(csp).toBeDefined();
      expect(csp!.value).toContain("default-src 'self'");
      expect(csp!.value).toContain("frame-ancestors 'none'");
      expect(csp!.value).toContain("base-uri 'self'");
      expect(csp!.value).toContain("form-action 'self'");
      expect(csp!.value).toContain('https://avatars.githubusercontent.com');
    });

    it('defines anti-clickjacking and standard security headers', async () => {
      const headersConfig = await nextConfig.headers!();
      const allHeaders = headersConfig.flatMap((h: { headers: Array<{ key: string; value: string }> }) => h.headers);

      const xFrame = allHeaders.find((h: { key: string }) => h.key === 'X-Frame-Options');
      expect(xFrame?.value).toBe('DENY');

      const xContent = allHeaders.find((h: { key: string }) => h.key === 'X-Content-Type-Options');
      expect(xContent?.value).toBe('nosniff');

      const hsts = allHeaders.find((h: { key: string }) => h.key === 'Strict-Transport-Security');
      expect(hsts?.value).toContain('max-age=63072000');

      const referrer = allHeaders.find((h: { key: string }) => h.key === 'Referrer-Policy');
      expect(referrer?.value).toBe('strict-origin-when-cross-origin');
    });

    it('poweredByHeader is disabled to prevent framework fingerprinting', () => {
      expect(nextConfig.poweredByHeader).toBe(false);
    });
  });

  // ─────────────────────────────────────────────────────────────
  // 2. Error Response Consistency & Information Leakage Prevention
  // ─────────────────────────────────────────────────────────────
  describe('Error Response Consistency & Security Audit', () => {
    it('standard AppErrors return structured error response with correct status', () => {
      const validationErr = new ValidationError('Bad input', [{ field: 'repo', message: 'required' }]);
      const res1 = formatErrorResponse(validationErr);
      expect(res1.status).toBe(400);
      expect(res1.body.error.code).toBe('VALIDATION_ERROR');
      expect(res1.body.error.details).toHaveLength(1);

      const notFoundErr = new NotFoundError('Item missing');
      const res2 = formatErrorResponse(notFoundErr);
      expect(res2.status).toBe(404);
      expect(res2.body.error.code).toBe('NOT_FOUND');

      const conflictErr = new ConflictError('State conflict');
      const res3 = formatErrorResponse(conflictErr);
      expect(res3.status).toBe(409);
      expect(res3.body.error.code).toBe('CONFLICT');
    });

    it('unknown errors produce generic 500 without leaking stack traces or internal messages', () => {
      const internalError = new Error('Database password was password123 at secret/path/db.ts:99');
      const formatted = formatErrorResponse(internalError);

      expect(formatted.status).toBe(500);
      expect(formatted.body.error.code).toBe('INTERNAL_ERROR');
      expect(formatted.body.error.message).toBe('An unexpected error occurred');
      expect(JSON.stringify(formatted.body)).not.toContain('password123');
      expect(JSON.stringify(formatted.body)).not.toContain('secret/path/db.ts');
      expect((formatted.body as unknown as Record<string, unknown>).stack).toBeUndefined();
    });

    it('non-Error objects thrown are sanitized into generic 500 responses', () => {
      const formatted = formatErrorResponse('string error');
      expect(formatted.status).toBe(500);
      expect(formatted.body.error.code).toBe('INTERNAL_ERROR');
      expect(formatted.body.error.message).toBe('An unexpected error occurred');
    });
  });

  // ─────────────────────────────────────────────────────────────
  // 3. Findings API Rate Limiting
  // ─────────────────────────────────────────────────────────────
  describe('Findings API Rate Limiting', () => {
    it('applies rate limit headers to findings responses', async () => {
      const scan = await Scan.create({
        userId: user1._id,
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        repositoryUrl: 'https://github.com/owner/repo',
        branch: 'main',
        status: 'completed',
        completedAt: new Date(),
      });

      const request = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}/findings`);
      const response = await getFindingsHandler(request, {
        params: Promise.resolve({ id: scan._id.toString() }),
      });

      expect(response.status).toBe(200);
      expect(response.headers.get('X-RateLimit-Limit')).toBe('100');
      expect(response.headers.get('X-RateLimit-Remaining')).toBe('99');
      expect(response.headers.get('X-RateLimit-Reset')).toBeDefined();
    });

    it('returns 429 when findings query rate limit (100 req/min) is exceeded', async () => {
      const scan = await Scan.create({
        userId: user1._id,
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        repositoryUrl: 'https://github.com/owner/repo',
        branch: 'main',
        status: 'completed',
        completedAt: new Date(),
      });

      // Simulate 100 requests
      for (let i = 0; i < 100; i++) {
        const req = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}/findings`);
        const res = await getFindingsHandler(req, {
          params: Promise.resolve({ id: scan._id.toString() }),
        });
        expect(res.status).toBe(200);
      }

      // 101st request should be blocked
      const req101 = new NextRequest(`http://localhost:3000/api/v1/scans/${scan._id}/findings`);
      const res101 = await getFindingsHandler(req101, {
        params: Promise.resolve({ id: scan._id.toString() }),
      });

      expect(res101.status).toBe(429);
      const json = await res101.json();
      expect(json.error.code).toBe('RATE_LIMIT_EXCEEDED');
      expect(res101.headers.get('Retry-After')).toBeDefined();
    });
  });

  // ─────────────────────────────────────────────────────────────
  // 4. Request Logging, Request ID & Sensitive Header Redaction
  // ─────────────────────────────────────────────────────────────
  describe('Request Logging Middleware & Tracing', () => {
    it('propagates incoming X-Request-Id or generates a new UUID header', async () => {
      const mockHandler = vi.fn().mockImplementation(() => NextResponse.json({ ok: true }));
      const wrappedHandler = withRequestLogging(mockHandler);

      // Case 1: Custom X-Request-Id provided
      const reqWithId = new NextRequest('http://localhost:3000/api/test', {
        headers: { 'x-request-id': 'custom-uuid-1234' },
      });
      const res1 = await wrappedHandler(reqWithId, {});
      expect(res1.headers.get('X-Request-Id')).toBe('custom-uuid-1234');

      // Case 2: No X-Request-Id provided (auto-generates UUID)
      const reqWithoutId = new NextRequest('http://localhost:3000/api/test');
      const res2 = await wrappedHandler(reqWithoutId, {});
      const generatedId = res2.headers.get('X-Request-Id');
      expect(generatedId).toBeDefined();
      expect(generatedId).toMatch(
        /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i
      );
    });

    it('redacts sensitive headers (authorization, cookie, token) in logs', () => {
      const headers = new Headers();
      headers.set('authorization', 'Bearer secret-jwt-token');
      headers.set('cookie', 'saferepo_session=secret_cookie_val');
      headers.set('accept', 'application/json');

      const sanitized = redactHeaders(headers);

      expect(sanitized.authorization).toBe('[REDACTED]');
      expect(sanitized.cookie).toBe('[REDACTED]');
      expect(sanitized.accept).toBe('application/json');
    });

    it('redactHeaders correctly masks all defined sensitive keys', () => {
      for (const sensitiveKey of SENSITIVE_HEADERS) {
        const raw = { [sensitiveKey]: 'my-secret-key-value' };
        const result = redactHeaders(raw);
        expect(result[sensitiveKey]).toBe('[REDACTED]');
      }
    });

    it('withRequestLogging catches, logs, and rethrows errors from handlers', async () => {
      const failingHandler = vi.fn().mockRejectedValue(new Error('Handler crashed'));
      const wrappedHandler = withRequestLogging(failingHandler);

      const request = new NextRequest('http://localhost:3000/api/failing');
      await expect(wrappedHandler(request, {})).rejects.toThrow('Handler crashed');
    });

    it('withRequestLogging includes userId in log context when authenticated session exists', async () => {
      const { logger } = await import('@/lib/logger');
      const loggerSpy = vi.spyOn(logger, 'info');
      const mockHandler = vi.fn().mockImplementation(() => NextResponse.json({ ok: true }));
      const wrappedHandler = withRequestLogging(mockHandler);

      const request = new NextRequest('http://localhost:3000/api/authenticated');
      const response = await wrappedHandler(request, {});

      expect(response.status).toBe(200);
      expect(loggerSpy).toHaveBeenCalledWith(
        expect.objectContaining({
          userId: user1._id.toString(),
          method: 'GET',
          path: '/api/authenticated',
        }),
        'API request completed'
      );
    });
  });

  // ─────────────────────────────────────────────────────────────
  // 5. Scan Enumeration Prevention (404 not 403)
  // ─────────────────────────────────────────────────────────────
  describe('Anti-Enumeration Boundary (Returns 404 for cross-user requests)', () => {
    it('returns 404 (not 403) when user1 attempts to delete user2 scan', async () => {
      const user2Scan = await Scan.create({
        userId: user2._id,
        repositoryOwner: 'user2',
        repositoryName: 'private-repo',
        repositoryUrl: 'https://github.com/user2/private-repo',
        branch: 'main',
        status: 'completed',
        completedAt: new Date(),
      });

      const request = new NextRequest(`http://localhost:3000/api/v1/scans/${user2Scan._id}`, {
        method: 'DELETE',
      });
      const response = await deleteScanHandler(request, {
        params: Promise.resolve({ id: user2Scan._id.toString() }),
      });

      // Crucial security invariant: MUST be 404, NEVER 403, to prevent ID harvesting
      expect(response.status).toBe(404);
      const json = await response.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });

    it('returns 404 (not 403) when user1 attempts to cancel user2 scan', async () => {
      const user2Scan = await Scan.create({
        userId: user2._id,
        repositoryOwner: 'user2',
        repositoryName: 'queued-repo',
        repositoryUrl: 'https://github.com/user2/queued-repo',
        branch: 'main',
        status: 'queued',
      });

      const request = new NextRequest(`http://localhost:3000/api/v1/scans/${user2Scan._id}/cancel`, {
        method: 'POST',
      });
      const response = await cancelScanHandler(request, {
        params: Promise.resolve({ id: user2Scan._id.toString() }),
      });

      expect(response.status).toBe(404);
      const json = await response.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });
  });
});
