import { describe, it, expect, beforeEach } from 'vitest';
import mongoose from 'mongoose';
import { Scan } from '@/models/scan';
import { User } from '@/models/user';

describe('Scan Model', () => {
  let userId: mongoose.Types.ObjectId;

  beforeEach(async () => {
    await Scan.deleteMany({});
    await User.deleteMany({});

    const user = await User.create({
      githubId: 'user-scan-test',
      username: 'scantester',
    });
    userId = user._id as mongoose.Types.ObjectId;
  });

  it('should create a scan with required fields and defaults', async () => {
    const scan = await Scan.create({
      userId,
      repositoryOwner: 'facebook',
      repositoryName: 'react',
      repositoryUrl: 'https://github.com/facebook/react',
      branch: 'main',
    });

    expect(scan._id).toBeInstanceOf(mongoose.Types.ObjectId);
    expect(scan.status).toBe('queued');
    expect(scan.branch).toBe('main');
    expect(scan.commitSha).toBeNull();
    expect(scan.error).toBeNull();
    expect(scan.scanners).toEqual(['semgrep', 'trivy', 'gitleaks', 'osv', 'npm-audit', 'pip-audit']);
    expect(scan.summary.total).toBe(0);
    expect(scan.createdAt).toBeInstanceOf(Date);
  });

  it('should require userId, repositoryOwner, repositoryName, and repositoryUrl', async () => {
    await expect(
      Scan.create({
        repositoryOwner: 'facebook',
        repositoryName: 'react',
      })
    ).rejects.toThrow();

    await expect(
      Scan.create({
        userId,
        repositoryName: 'react',
      })
    ).rejects.toThrow();
  });

  it('should validate status enum', async () => {
    await expect(
      Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        repositoryUrl: 'https://github.com/owner/repo',
        branch: 'main',
        status: 'invalid-status' as unknown as 'queued',
      })
    ).rejects.toThrow();
  });

  it('should update scan status and summary', async () => {
    const scan = await Scan.create({
      userId,
      repositoryOwner: 'owner',
      repositoryName: 'repo',
      repositoryUrl: 'https://github.com/owner/repo',
      branch: 'main',
    });

    scan.status = 'completed';
    scan.summary.critical = 2;
    scan.summary.total = 2;
    scan.commitSha = 'abcdef123456';
    await scan.save();

    const updated = await Scan.findById(scan._id);
    expect(updated?.status).toBe('completed');
    expect(updated?.summary.critical).toBe(2);
    expect(updated?.commitSha).toBe('abcdef123456');
  });
});
