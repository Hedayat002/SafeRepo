import { describe, it, expect, beforeEach } from 'vitest';
import mongoose from 'mongoose';
import { Session } from '@/models/session';
import { User } from '@/models/user';

describe('Session Model', () => {
  let userId: mongoose.Types.ObjectId;

  beforeEach(async () => {
    await Session.deleteMany({});
    await User.deleteMany({});
    const user = await User.create({ githubId: 'sess-user', username: 'sessuser' });
    userId = user._id;
  });

  it('should create a session with required fields', async () => {
    const session = await Session.create({
      sessionId: 'test-session-id',
      userId,
      githubAccessToken: 'ghu_testtoken123',
      expiresAt: new Date(Date.now() + 86400000),
    });

    expect(session.sessionId).toBe('test-session-id');
    expect(session.userId.toString()).toBe(userId.toString());
    expect(session.githubAccessToken).toBe('ghu_testtoken123');
    expect(session.expiresAt).toBeInstanceOf(Date);
    expect(session.createdAt).toBeInstanceOf(Date);
  });

  it('should enforce unique sessionId', async () => {
    await Session.create({
      sessionId: 'unique-session',
      userId,
      githubAccessToken: 'token1',
      expiresAt: new Date(Date.now() + 86400000),
    });

    await expect(
      Session.create({
        sessionId: 'unique-session',
        userId,
        githubAccessToken: 'token2',
        expiresAt: new Date(Date.now() + 86400000),
      })
    ).rejects.toThrow();
  });

  it('should require sessionId', async () => {
    await expect(
      Session.create({
        userId,
        githubAccessToken: 'token',
        expiresAt: new Date(Date.now() + 86400000),
      })
    ).rejects.toThrow();
  });

  it('should require userId', async () => {
    await expect(
      Session.create({
        sessionId: 'no-user',
        githubAccessToken: 'token',
        expiresAt: new Date(Date.now() + 86400000),
      })
    ).rejects.toThrow();
  });

  it('should require githubAccessToken', async () => {
    await expect(
      Session.create({
        sessionId: 'no-token',
        userId,
        expiresAt: new Date(Date.now() + 86400000),
      })
    ).rejects.toThrow();
  });

  it('should require expiresAt', async () => {
    await expect(
      Session.create({
        sessionId: 'no-expiry',
        userId,
        githubAccessToken: 'token',
      })
    ).rejects.toThrow();
  });

  it('should find session by sessionId', async () => {
    await Session.create({
      sessionId: 'findable-session',
      userId,
      githubAccessToken: 'token',
      expiresAt: new Date(Date.now() + 86400000),
    });

    const found = await Session.findOne({ sessionId: 'findable-session' });
    expect(found).not.toBeNull();
    expect(found?.userId.toString()).toBe(userId.toString());
  });

  it('should find all sessions by userId', async () => {
    await Session.create({
      sessionId: 'sess-1',
      userId,
      githubAccessToken: 'token1',
      expiresAt: new Date(Date.now() + 86400000),
    });
    await Session.create({
      sessionId: 'sess-2',
      userId,
      githubAccessToken: 'token2',
      expiresAt: new Date(Date.now() + 86400000),
    });

    const sessions = await Session.find({ userId });
    expect(sessions).toHaveLength(2);
  });

  it('should delete a session', async () => {
    await Session.create({
      sessionId: 'delete-me',
      userId,
      githubAccessToken: 'token',
      expiresAt: new Date(Date.now() + 86400000),
    });

    await Session.deleteOne({ sessionId: 'delete-me' });
    const found = await Session.findOne({ sessionId: 'delete-me' });
    expect(found).toBeNull();
  });
});
