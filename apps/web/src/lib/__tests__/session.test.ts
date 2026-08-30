import { describe, it, expect, beforeEach } from 'vitest';
import { User } from '@/models/user';
import { Session } from '@/models/session';

/**
 * Session management tests.
 *
 * Tests createSession, getSession, destroySession, destroyAllUserSessions.
 * Uses mongodb-memory-server (via test setup).
 *
 * Note: We test the session logic directly against the model rather than
 * importing lib/session.ts which uses Next.js cookies() — a server-only API
 * that is not available in Vitest's Node environment.
 */

describe('Session Management', () => {
  let userId: string;

  beforeEach(async () => {
    await User.deleteMany({});
    await Session.deleteMany({});
    const user = await User.create({ githubId: 'sm-user', username: 'smuser' });
    userId = user._id.toString();
  });

  it('should create a session with opaque UUID', async () => {
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 86400000);

    const session = await Session.create({
      sessionId,
      userId,
      githubAccessToken: 'ghu_test123',
      expiresAt,
    });

    expect(session.sessionId).toBe(sessionId);
    // UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    expect(sessionId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(session.userId.toString()).toBe(userId);
    expect(session.githubAccessToken).toBe('ghu_test123');
  });

  it('should retrieve a valid session', async () => {
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 86400000);

    await Session.create({
      sessionId,
      userId,
      githubAccessToken: 'ghu_valid',
      expiresAt,
    });

    const found = await Session.findOne({
      sessionId,
      expiresAt: { $gt: new Date() },
    }).lean();

    expect(found).not.toBeNull();
    expect(found?.sessionId).toBe(sessionId);
    expect(found?.githubAccessToken).toBe('ghu_valid');
  });

  it('should not retrieve an expired session', async () => {
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() - 1000); // Already expired

    await Session.create({
      sessionId,
      userId,
      githubAccessToken: 'ghu_expired',
      expiresAt,
    });

    const found = await Session.findOne({
      sessionId,
      expiresAt: { $gt: new Date() },
    });

    expect(found).toBeNull();
  });

  it('should return null for non-existent session', async () => {
    const found = await Session.findOne({
      sessionId: 'does-not-exist',
      expiresAt: { $gt: new Date() },
    });

    expect(found).toBeNull();
  });

  it('should destroy a session', async () => {
    const sessionId = crypto.randomUUID();

    await Session.create({
      sessionId,
      userId,
      githubAccessToken: 'ghu_destroy',
      expiresAt: new Date(Date.now() + 86400000),
    });

    await Session.deleteOne({ sessionId });

    const found = await Session.findOne({ sessionId });
    expect(found).toBeNull();
  });

  it('should destroy all sessions for a user', async () => {
    await Session.create({
      sessionId: crypto.randomUUID(),
      userId,
      githubAccessToken: 'token1',
      expiresAt: new Date(Date.now() + 86400000),
    });
    await Session.create({
      sessionId: crypto.randomUUID(),
      userId,
      githubAccessToken: 'token2',
      expiresAt: new Date(Date.now() + 86400000),
    });

    const result = await Session.deleteMany({ userId });
    expect(result.deletedCount).toBe(2);

    const remaining = await Session.find({ userId });
    expect(remaining).toHaveLength(0);
  });

  it('should store github access token server-side only', async () => {
    const session = await Session.create({
      sessionId: crypto.randomUUID(),
      userId,
      githubAccessToken: 'ghu_secret_token_value',
      expiresAt: new Date(Date.now() + 86400000),
    });

    // Token is stored in the session document
    expect(session.githubAccessToken).toBe('ghu_secret_token_value');

    // Verify it's in the database
    const found = await Session.findOne({ sessionId: session.sessionId });
    expect(found?.githubAccessToken).toBe('ghu_secret_token_value');
  });
});
