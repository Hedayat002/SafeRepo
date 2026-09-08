import { describe, it, expect, beforeEach } from 'vitest';
import mongoose from 'mongoose';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import { cleanupExpiredScans } from '../retention';

describe('Phase 08 — Scan Data Retention & Cleanup', () => {
  const userId = new mongoose.Types.ObjectId();
  const otherUserId = new mongoose.Types.ObjectId();

  beforeEach(async () => {
    await Scan.deleteMany({});
    await Finding.deleteMany({});
  });

  async function createFinding(scanId: mongoose.Types.ObjectId, ownerId: mongoose.Types.ObjectId = userId) {
    return Finding.create({
      scanId,
      userId: ownerId,
      scanner: 'semgrep',
      category: 'sast',
      severity: 'high',
      title: 'SQL Injection',
      description: 'Potential SQL injection vulnerability',
      file: 'src/db.ts',
      line: 42,
      fingerprint: new mongoose.Types.ObjectId().toString(),
    });
  }

  describe('TTL Expiration Cleanup', () => {
    it('deletes completed scans older than retentionDays', async () => {
      const oldCompletedAt = new Date(Date.now() - 95 * 24 * 60 * 60 * 1000); // 95 days ago
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        repositoryUrl: 'https://github.com/owner/repo',
        branch: 'main',
        status: 'completed',
        completedAt: oldCompletedAt,
      });

      const result = await cleanupExpiredScans({ retentionDays: 90 });

      expect(result.deletedScansCount).toBe(1);
      const found = await Scan.findById(scan._id);
      expect(found).toBeNull();
    });

    it('deletes failed and timed_out scans older than retentionDays', async () => {
      const oldCompletedAt = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000);
      const failedScan = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'repo-fail',
        repositoryUrl: 'https://github.com/owner/repo-fail',
        branch: 'main',
        status: 'failed',
        error: 'Scan runner failed',
        completedAt: oldCompletedAt,
      });
      const timedOutScan = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'repo-timeout',
        repositoryUrl: 'https://github.com/owner/repo-timeout',
        branch: 'main',
        status: 'timed_out',
        error: 'Timeout exceeded',
        completedAt: oldCompletedAt,
      });

      const result = await cleanupExpiredScans({ retentionDays: 90 });

      expect(result.deletedScansCount).toBe(2);
      expect(await Scan.findById(failedScan._id)).toBeNull();
      expect(await Scan.findById(timedOutScan._id)).toBeNull();
    });

    it('cascades deletion to associated findings when scan expires', async () => {
      const oldCompletedAt = new Date(Date.now() - 95 * 24 * 60 * 60 * 1000);
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        repositoryUrl: 'https://github.com/owner/repo',
        branch: 'main',
        status: 'completed',
        completedAt: oldCompletedAt,
      });

      await createFinding(scan._id);
      await createFinding(scan._id);

      expect(await Finding.countDocuments({ scanId: scan._id })).toBe(2);

      const result = await cleanupExpiredScans({ retentionDays: 90 });

      expect(result.deletedScansCount).toBe(1);
      expect(result.deletedFindingsCount).toBe(2);
      expect(await Finding.countDocuments({ scanId: scan._id })).toBe(0);
    });

    it('preserves completed scans within the retention window', async () => {
      const recentCompletedAt = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000); // 30 days ago
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'repo',
        repositoryUrl: 'https://github.com/owner/repo',
        branch: 'main',
        status: 'completed',
        completedAt: recentCompletedAt,
      });

      await createFinding(scan._id);

      const result = await cleanupExpiredScans({ retentionDays: 90 });

      expect(result.deletedScansCount).toBe(0);
      expect(result.deletedFindingsCount).toBe(0);
      expect(await Scan.findById(scan._id)).not.toBeNull();
      expect(await Finding.countDocuments({ scanId: scan._id })).toBe(1);
    });

    it('never deletes in-progress scans (queued, cloning, scanning, normalizing) even if old', async () => {
      const oldDate = new Date(Date.now() - 120 * 24 * 60 * 60 * 1000);
      const queued = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'r1',
        repositoryUrl: 'https://github.com/owner/r1',
        branch: 'main',
        status: 'queued',
        createdAt: oldDate,
        updatedAt: oldDate,
      });
      const cloning = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'r2',
        repositoryUrl: 'https://github.com/owner/r2',
        branch: 'main',
        status: 'cloning',
        createdAt: oldDate,
        updatedAt: oldDate,
      });
      const scanning = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'r3',
        repositoryUrl: 'https://github.com/owner/r3',
        branch: 'main',
        status: 'scanning',
        createdAt: oldDate,
        updatedAt: oldDate,
      });
      const normalizing = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'r4',
        repositoryUrl: 'https://github.com/owner/r4',
        branch: 'main',
        status: 'normalizing',
        createdAt: oldDate,
        updatedAt: oldDate,
      });

      const result = await cleanupExpiredScans({ retentionDays: 90 });

      expect(result.deletedScansCount).toBe(0);
      expect(await Scan.findById(queued._id)).not.toBeNull();
      expect(await Scan.findById(cloning._id)).not.toBeNull();
      expect(await Scan.findById(scanning._id)).not.toBeNull();
      expect(await Scan.findById(normalizing._id)).not.toBeNull();
    });

    it('handles terminal scan with completedAt null by checking updatedAt', async () => {
      const oldDate = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000);
      const scan = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'null-completed-at',
        repositoryUrl: 'https://github.com/owner/null-completed-at',
        branch: 'main',
        status: 'failed',
        completedAt: null,
      });

      // Explicitly set updatedAt to old date with timestamps disabled
      await Scan.updateOne({ _id: scan._id }, { $set: { updatedAt: oldDate } }, { timestamps: false });

      const result = await cleanupExpiredScans({ retentionDays: 90 });

      expect(result.deletedScansCount).toBe(1);
      expect(await Scan.findById(scan._id)).toBeNull();
    });

    it('returns zero counts when database is empty', async () => {
      const result = await cleanupExpiredScans({ retentionDays: 90 });

      expect(result.deletedScansCount).toBe(0);
      expect(result.deletedFindingsCount).toBe(0);
      expect(result.prunedUserScansCount).toBe(0);
    });
  });

  describe('Per-User Scan Cap Enforcement', () => {
    it('does not prune when user scan count is below or equal to the cap', async () => {
      for (let i = 0; i < 3; i++) {
        await Scan.create({
          userId,
          repositoryOwner: 'owner',
          repositoryName: `repo-${i}`,
          repositoryUrl: `https://github.com/owner/repo-${i}`,
          branch: 'main',
          status: 'completed',
          completedAt: new Date(),
        });
      }

      const result = await cleanupExpiredScans({ retentionDays: 90, maxScansPerUser: 5 });

      expect(result.prunedUserScansCount).toBe(0);
      expect(await Scan.countDocuments({ userId })).toBe(3);
    });

    it('prunes the oldest terminal scans when user exceeds scan cap', async () => {
      const scans = [];
      const baseTime = Date.now() - 10_000;

      for (let i = 0; i < 5; i++) {
        const scan = await Scan.create({
          userId,
          repositoryOwner: 'owner',
          repositoryName: `repo-${i}`,
          repositoryUrl: `https://github.com/owner/repo-${i}`,
          branch: 'main',
          status: 'completed',
          completedAt: new Date(),
          createdAt: new Date(baseTime + i * 1000),
        });
        scans.push(scan);
      }

      expect(await Scan.countDocuments({ userId })).toBe(5);

      // Set cap to 3: the 2 oldest scans (indices 0 and 1) should be pruned
      const result = await cleanupExpiredScans({ retentionDays: 90, maxScansPerUser: 3 });

      expect(result.prunedUserScansCount).toBe(2);
      expect(await Scan.countDocuments({ userId })).toBe(3);

      expect(await Scan.findById(scans[0]._id)).toBeNull();
      expect(await Scan.findById(scans[1]._id)).toBeNull();
      expect(await Scan.findById(scans[2]._id)).not.toBeNull();
      expect(await Scan.findById(scans[3]._id)).not.toBeNull();
      expect(await Scan.findById(scans[4]._id)).not.toBeNull();
    });

    it('cascades deletion of findings for cap-pruned scans', async () => {
      const baseTime = Date.now() - 10_000;
      const oldestScan = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'oldest',
        repositoryUrl: 'https://github.com/owner/oldest',
        branch: 'main',
        status: 'completed',
        completedAt: new Date(),
        createdAt: new Date(baseTime),
      });

      await createFinding(oldestScan._id);
      await createFinding(oldestScan._id);

      const newerScan = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'newer',
        repositoryUrl: 'https://github.com/owner/newer',
        branch: 'main',
        status: 'completed',
        completedAt: new Date(),
        createdAt: new Date(baseTime + 1000),
      });

      // Cap of 1 forces pruning of oldestScan
      const result = await cleanupExpiredScans({ retentionDays: 90, maxScansPerUser: 1 });

      expect(result.prunedUserScansCount).toBe(1);
      expect(result.deletedFindingsCount).toBe(2);
      expect(await Scan.findById(oldestScan._id)).toBeNull();
      expect(await Finding.countDocuments({ scanId: oldestScan._id })).toBe(0);
      expect(await Scan.findById(newerScan._id)).not.toBeNull();
    });

    it('never prunes active scans during cap enforcement', async () => {
      const baseTime = Date.now() - 10_000;

      // Active scan created first
      const activeScan = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'active-scan',
        repositoryUrl: 'https://github.com/owner/active-scan',
        branch: 'main',
        status: 'scanning',
        createdAt: new Date(baseTime),
      });

      // Terminal scan created later
      const terminalScan = await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'terminal-scan',
        repositoryUrl: 'https://github.com/owner/terminal-scan',
        branch: 'main',
        status: 'completed',
        completedAt: new Date(),
        createdAt: new Date(baseTime + 1000),
      });

      // Total = 2 scans, cap = 1. Only terminal scan can be pruned, active scan MUST survive.
      const result = await cleanupExpiredScans({ retentionDays: 90, maxScansPerUser: 1 });

      expect(result.prunedUserScansCount).toBe(1);
      expect(await Scan.findById(activeScan._id)).not.toBeNull();
      expect(await Scan.findById(terminalScan._id)).toBeNull();
    });

    it('isolates users so only the exceeding user is pruned', async () => {
      // User 1 has 3 scans
      for (let i = 0; i < 3; i++) {
        await Scan.create({
          userId,
          repositoryOwner: 'u1',
          repositoryName: `r-${i}`,
          repositoryUrl: `https://github.com/u1/r-${i}`,
          branch: 'main',
          status: 'completed',
          completedAt: new Date(),
        });
      }

      // User 2 has 1 scan
      const u2Scan = await Scan.create({
        userId: otherUserId,
        repositoryOwner: 'u2',
        repositoryName: 'r-0',
        repositoryUrl: 'https://github.com/u2/r-0',
        branch: 'main',
        status: 'completed',
        completedAt: new Date(),
      });

      // Cap = 2
      const result = await cleanupExpiredScans({ retentionDays: 90, maxScansPerUser: 2 });

      expect(result.prunedUserScansCount).toBe(1);
      expect(await Scan.countDocuments({ userId })).toBe(2);
      expect(await Scan.countDocuments({ userId: otherUserId })).toBe(1);
      expect(await Scan.findById(u2Scan._id)).not.toBeNull();
    });

    it('handles user with only active scans exceeding cap gracefully without pruning', async () => {
      // User has 3 active scans, cap is 2
      for (let i = 0; i < 3; i++) {
        await Scan.create({
          userId,
          repositoryOwner: 'u1',
          repositoryName: `active-${i}`,
          repositoryUrl: `https://github.com/u1/active-${i}`,
          branch: 'main',
          status: 'cloning',
        });
      }

      const result = await cleanupExpiredScans({ maxScansPerUser: 2 });

      expect(result.prunedUserScansCount).toBe(0);
      expect(await Scan.countDocuments({ userId })).toBe(3);
    });

    it('correctly uses environment defaults when no options are provided', async () => {
      const recentCompletedAt = new Date();
      await Scan.create({
        userId,
        repositoryOwner: 'owner',
        repositoryName: 'recent-scan',
        repositoryUrl: 'https://github.com/owner/recent-scan',
        branch: 'main',
        status: 'completed',
        completedAt: recentCompletedAt,
      });

      const result = await cleanupExpiredScans();

      expect(result.deletedScansCount).toBe(0);
      expect(result.deletedFindingsCount).toBe(0);
      expect(result.prunedUserScansCount).toBe(0);
    });

    it('prunes multiple batches of excess scans across multiple users simultaneously', async () => {
      // User 1 has 4 scans, User 2 has 4 scans. Cap = 2.
      for (let i = 0; i < 4; i++) {
        await Scan.create({
          userId,
          repositoryOwner: 'u1',
          repositoryName: `u1-r-${i}`,
          repositoryUrl: `https://github.com/u1/u1-r-${i}`,
          branch: 'main',
          status: 'completed',
          completedAt: new Date(),
        });
        await Scan.create({
          userId: otherUserId,
          repositoryOwner: 'u2',
          repositoryName: `u2-r-${i}`,
          repositoryUrl: `https://github.com/u2/u2-r-${i}`,
          branch: 'main',
          status: 'failed',
          completedAt: new Date(),
        });
      }

      const result = await cleanupExpiredScans({ maxScansPerUser: 2 });

      expect(result.prunedUserScansCount).toBe(4);
      expect(await Scan.countDocuments({ userId })).toBe(2);
      expect(await Scan.countDocuments({ userId: otherUserId })).toBe(2);
    });
  });
});
