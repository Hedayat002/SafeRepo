import { env } from '@/lib/env';
import { logger } from '@/lib/logger';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';

export interface RetentionCleanupOptions {
  retentionDays?: number;
  maxScansPerUser?: number;
}

export interface RetentionCleanupResult {
  deletedScansCount: number;
  deletedFindingsCount: number;
  prunedUserScansCount: number;
}

const TERMINAL_STATUSES = ['completed', 'failed', 'timed_out'] as const;

/**
 * Cleans up expired scans past the retention window and enforces the per-user scan cap.
 *
 * Terminal scans (completed, failed, timed_out) older than `retentionDays` are deleted along
 * with their associated findings.
 *
 * Scans exceeding `maxScansPerUser` per user are pruned starting with the oldest terminal scans.
 * In-progress scans (queued, cloning, scanning, normalizing) are NEVER pruned.
 */
export async function cleanupExpiredScans(
  options: RetentionCleanupOptions = {}
): Promise<RetentionCleanupResult> {
  const retentionDays = options.retentionDays ?? env.SCAN_RETENTION_DAYS;
  const maxScansPerUser = options.maxScansPerUser ?? env.MAX_SCANS_PER_USER;

  const cutoffDate = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000);

  let deletedScansCount = 0;
  let deletedFindingsCount = 0;
  let prunedUserScansCount = 0;

  // 1. Find expired terminal scans
  const expiredScans = await Scan.find({
    status: { $in: TERMINAL_STATUSES },
    $or: [
      { completedAt: { $lt: cutoffDate } },
      { completedAt: null, updatedAt: { $lt: cutoffDate } },
    ],
  })
    .select('_id')
    .lean();

  if (expiredScans.length > 0) {
    const expiredScanIds = expiredScans.map((s) => s._id);

    const findingsDeleteResult = await Finding.deleteMany({
      scanId: { $in: expiredScanIds },
    });
    deletedFindingsCount += findingsDeleteResult.deletedCount ?? 0;

    const scansDeleteResult = await Scan.deleteMany({
      _id: { $in: expiredScanIds },
    });
    deletedScansCount += scansDeleteResult.deletedCount ?? 0;

    logger.info(
      { deletedScansCount, deletedFindingsCount, cutoffDate: cutoffDate.toISOString() },
      'Expired scan retention cleanup completed'
    );
  }

  // 2. Enforce per-user scan cap
  // Find users whose total scan count exceeds maxScansPerUser
  const userCounts = await Scan.aggregate([
    { $group: { _id: '$userId', total: { $sum: 1 } } },
    { $match: { total: { $gt: maxScansPerUser } } },
  ]);

  for (const userGroup of userCounts) {
    const userId = userGroup._id;
    const excessCount = userGroup.total - maxScansPerUser;

    if (excessCount <= 0) continue;

    // Find oldest terminal scans for this user to prune
    const excessTerminalScans = await Scan.find({
      userId,
      status: { $in: TERMINAL_STATUSES },
    })
      .sort({ createdAt: 1 })
      .limit(excessCount)
      .select('_id')
      .lean();

    if (excessTerminalScans.length > 0) {
      const pruneScanIds = excessTerminalScans.map((s) => s._id);

      const findingsDeleteResult = await Finding.deleteMany({
        scanId: { $in: pruneScanIds },
      });
      deletedFindingsCount += findingsDeleteResult.deletedCount ?? 0;

      const scansDeleteResult = await Scan.deleteMany({
        _id: { $in: pruneScanIds },
      });
      const prunedCount = scansDeleteResult.deletedCount ?? 0;
      prunedUserScansCount += prunedCount;
      deletedScansCount += prunedCount;

      logger.info(
        { userId: String(userId), prunedCount, excessTarget: excessCount },
        'User scan cap enforced: pruned oldest terminal scans'
      );
    }
  }

  return {
    deletedScansCount,
    deletedFindingsCount,
    prunedUserScansCount,
  };
}
