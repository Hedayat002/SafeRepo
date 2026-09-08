import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { connectDB } from '@/lib/db';
import { Scan } from '@/models/scan';
import { scanIdParamSchema } from '@/lib/schemas';
import {
  formatErrorResponse,
  ValidationError,
  NotFoundError,
  ConflictError,
} from '@/lib/errors';

/**
 * POST /api/v1/scans/:id/cancel
 *
 * Cancels a queued or in-progress scan.
 * - Requires authentication.
 * - Validates scanId parameter format.
 * - Enforces user authorization (returns 404 if not found or belongs to another user).
 * - Rejects cancellation of terminal scans with 409 Conflict.
 * - For 'queued' scans: immediately transitions to 'failed' with error "Cancelled by user".
 * - For in-progress scans ('cloning', 'scanning', 'normalizing'): sets cancelRequested: true
 *   so the executing worker aborts gracefully upon next heartbeat check.
 * - Returns 200 OK with the updated scan data.
 */
export async function POST(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> }
): Promise<NextResponse> {
  try {
    const { user } = await requireAuth();
    const params = await context.params;

    const parseResult = scanIdParamSchema.safeParse(params);
    if (!parseResult.success) {
      throw new ValidationError('Invalid scan ID parameter', parseResult.error.issues);
    }

    const { id } = parseResult.data;

    await connectDB();

    const scan = await Scan.findOne({ _id: id, userId: user._id });

    if (!scan) {
      // 404 both if scan doesn't exist or belongs to another user (anti-enumeration)
      throw new NotFoundError(`Scan ${id} not found`);
    }

    const terminalStatuses = ['completed', 'failed', 'timed_out'];
    if (terminalStatuses.includes(scan.status)) {
      throw new ConflictError(
        `Cannot cancel scan ${id} because it has already reached a terminal state (${scan.status})`
      );
    }

    let updatedScan;

    if (scan.status === 'queued') {
      // For queued scans, transition immediately to failed (cancelled)
      updatedScan = await Scan.findOneAndUpdate(
        { _id: id, userId: user._id, status: 'queued' },
        {
          $set: {
            status: 'failed',
            error: 'Cancelled by user',
            completedAt: new Date(),
          },
        },
        { returnDocument: 'after' }
      );
    } else {
      // For active scans (cloning, scanning, normalizing), signal cancellation to worker
      updatedScan = await Scan.findOneAndUpdate(
        { _id: id, userId: user._id },
        {
          $set: {
            cancelRequested: true,
          },
        },
        { returnDocument: 'after' }
      );
    }

    if (!updatedScan) {
      throw new NotFoundError(`Scan ${id} not found`);
    }

    return NextResponse.json({
      data: {
        id: updatedScan._id.toString(),
        repositoryOwner: updatedScan.repositoryOwner,
        repositoryName: updatedScan.repositoryName,
        repositoryUrl: updatedScan.repositoryUrl,
        branch: updatedScan.branch,
        commitSha: updatedScan.commitSha,
        status: updatedScan.status,
        cancelRequested: updatedScan.cancelRequested,
        scanners: updatedScan.scanners,
        summary: updatedScan.summary,
        error: updatedScan.error,
        startedAt: updatedScan.startedAt,
        completedAt: updatedScan.completedAt,
        duration: updatedScan.duration,
        createdAt: updatedScan.createdAt,
        updatedAt: updatedScan.updatedAt,
      },
    });
  } catch (err) {
    const { body, status } = formatErrorResponse(err);
    return NextResponse.json(body, { status });
  }
}
