import { describe, it, expect, beforeEach, vi } from 'vitest';
import { User } from '@/models/user';
import { Session } from '@/models/session';
import { GET as getMeHandler } from '@/app/api/v1/auth/me/route';
import { POST as logoutHandler } from '@/app/api/v1/auth/logout/route';
import * as sessionModule from '@/lib/session';

describe('Auth API Routes', () => {
  beforeEach(async () => {
    await User.deleteMany({});
    await Session.deleteMany({});
  });

  describe('GET /api/v1/auth/me', () => {
    it('should return 401 when not authenticated', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(undefined);

      const response = await getMeHandler();
      expect(response.status).toBe(401);

      const json = await response.json();
      expect(json.error.code).toBe('UNAUTHORIZED');
    });

    it('should return user profile when authenticated', async () => {
      const user = await User.create({
        githubId: 'auth-test-id',
        username: 'octocat',
        displayName: 'The Octocat',
        email: 'octocat@github.com',
        avatarUrl: 'https://github.com/images/error/octocat_happy.gif',
      });

      const session = await Session.create({
        sessionId: 'valid-session-id-123',
        userId: user._id,
        githubAccessToken: 'ghu_dummy_token',
        expiresAt: new Date(Date.now() + 86400000),
      });

      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session.sessionId);

      const response = await getMeHandler();
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.user.id).toBe(user._id.toString());
      expect(json.user.username).toBe('octocat');
      expect(json.user.displayName).toBe('The Octocat');
      expect(json.user.avatarUrl).toBe('https://github.com/images/error/octocat_happy.gif');
      // Ensure githubAccessToken and internal session details are never returned
      expect(json.user.githubAccessToken).toBeUndefined();
    });
  });

  describe('POST /api/v1/auth/logout', () => {
    it('should return 401 when not authenticated', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(undefined);

      const response = await logoutHandler();
      expect(response.status).toBe(401);

      const json = await response.json();
      expect(json.error.code).toBe('UNAUTHORIZED');
    });

    it('should destroy session and return success when authenticated', async () => {
      const user = await User.create({
        githubId: 'logout-user-id',
        username: 'logoutuser',
      });

      const session = await Session.create({
        sessionId: 'logout-session-123',
        userId: user._id,
        githubAccessToken: 'ghu_dummy_token',
        expiresAt: new Date(Date.now() + 86400000),
      });

      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session.sessionId);
      const clearCookieSpy = vi.spyOn(sessionModule, 'clearSessionCookie').mockResolvedValue(undefined);

      const response = await logoutHandler();
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.message).toBe('Logged out');

      // Verify session was destroyed in DB
      const sessionInDb = await Session.findOne({ sessionId: session.sessionId });
      expect(sessionInDb).toBeNull();
      expect(clearCookieSpy).toHaveBeenCalled();
    });
  });
});
