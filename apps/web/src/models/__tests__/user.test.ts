import { describe, it, expect, beforeEach } from 'vitest';
import mongoose from 'mongoose';
import { User } from '@/models/user';

describe('User Model', () => {
  beforeEach(async () => {
    await User.deleteMany({});
  });

  it('should create a user with required fields', async () => {
    const user = await User.create({
      githubId: '12345',
      username: 'testuser',
    });

    expect(user.githubId).toBe('12345');
    expect(user.username).toBe('testuser');
    expect(user.displayName).toBeNull();
    expect(user.email).toBeNull();
    expect(user.avatarUrl).toBeNull();
    expect(user.createdAt).toBeInstanceOf(Date);
    expect(user.updatedAt).toBeInstanceOf(Date);
    expect(user._id).toBeInstanceOf(mongoose.Types.ObjectId);
  });

  it('should create a user with all fields', async () => {
    const user = await User.create({
      githubId: '67890',
      username: 'fulluser',
      displayName: 'Full User',
      email: 'full@example.com',
      avatarUrl: 'https://example.com/avatar.png',
    });

    expect(user.displayName).toBe('Full User');
    expect(user.email).toBe('full@example.com');
    expect(user.avatarUrl).toBe('https://example.com/avatar.png');
  });

  it('should enforce unique githubId', async () => {
    await User.create({ githubId: 'unique1', username: 'user1' });

    await expect(
      User.create({ githubId: 'unique1', username: 'user2' })
    ).rejects.toThrow();
  });

  it('should require githubId', async () => {
    await expect(
      User.create({ username: 'noGithubId' })
    ).rejects.toThrow();
  });

  it('should require username', async () => {
    await expect(
      User.create({ githubId: '99999' })
    ).rejects.toThrow();
  });

  it('should find user by githubId', async () => {
    await User.create({ githubId: 'findme', username: 'findable' });

    const found = await User.findOne({ githubId: 'findme' });
    expect(found).not.toBeNull();
    expect(found?.username).toBe('findable');
  });

  it('should update user fields', async () => {
    const user = await User.create({ githubId: 'update1', username: 'original' });

    await User.findByIdAndUpdate(user._id, { username: 'updated' });

    const updated = await User.findById(user._id);
    expect(updated?.username).toBe('updated');
  });
});
