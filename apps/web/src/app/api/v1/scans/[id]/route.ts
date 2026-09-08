import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { connectDB } from '@/lib/db';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import { scanIdParamSchema } from '@/lib/schemas';
import {
  formatErrorResponse,
  ValidationError,
  NotFoundError,
  ConflictError,
} from '@/lib/errors';
import { checkRateLimit, applyRateLimitHeaders } from '@/lib/rate-limit';

/**
 * GET /api/v1/scans/:id
 *
 * Retrieves details and status of a specific scan.
 * - Requires authentication.
 * - Validates scanId parameter format.
 * - Enforces user authorization (users can only access their own scans).
 */
export async function GET(
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

    const scan = await Scan.findOne({ _id: id, userId: user._id }).lean();

    if (!scan) {
      // 404 both if scan doesn't exist or belongs to another user (anti-enumeration)
      throw new NotFoundError(`Scan ${id} not found`);
    }

    return NextResponse.json({
      data: {
        id: scan._id.toString(),
        repositoryOwner: scan.repositoryOwner,
        repositoryName: scan.repositoryName,
        repositoryUrl: scan.repositoryUrl,
        branch: scan.branch,
        commitSha: scan.commitSha,
        status: scan.status,
        scanners: scan.scanners,
        summary: scan.summary,
        error: scan.error,
        startedAt: scan.startedAt,
        completedAt: scan.completedAt,
        duration: scan.duration,
        createdAt: scan.createdAt,
        updatedAt: scan.updatedAt,
      },
    });
  } catch (err) {
    const { body, status } = formatErrorResponse(err);
    return NextResponse.json(body, { status });
  }
}

/**
 * DELETE /api/v1/scans/:id
 *
 * Deletes a completed scan and cascade-deletes its associated findings.
 * - Requires authentication.
 * - Validates scanId parameter format.
 * - Enforces user authorization (returns 404 if not found or belongs to another user).
 * - Rate-limited: 10 deletions per minute per user.
 * - Rejects deletion of in-progress scans (409 Conflict).
 * - Cascade-deletes all findings associated with the scan.
 * - Returns 204 No Content on success.
 */
export async function DELETE(
  _request: NextRequest,
  context: { params: Promise<{ id: string }> }
): Promise<NextResponse> {
  try {
    const { user } = await requireAuth();

    // Rate limiting: 10 deletions per minute per user
    const rateLimitResult = checkRateLimit(`scan-delete:${user._id.toString()}`, {
      maxRequests: 10,
      windowMs: 60 * 1000,
    });

    if (!rateLimitResult.allowed) {
      const response = NextResponse.json(
        {
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Scan deletion rate limit exceeded. Please retry later.',
          },
        },
        { status: 429 }
      );
      applyRateLimitHeaders(response.headers, rateLimitResult);
      return response;
    }

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

    // Reject deletion of in-progress scans (409 Conflict)
    const inProgressStatuses = ['queued', 'cloning', 'scanning', 'normalizing'];
    if (inProgressStatuses.includes(scan.status)) {
      throw new ConflictError(
        `Cannot delete scan ${id} because it is currently in progress (${scan.status}). Cancel it first or wait for completion.`
      );
    }

    // Cascade delete findings and scan
    await Promise.all([
      Finding.deleteMany({ scanId: id }),
      Scan.deleteOne({ _id: id }),
    ]);

    const response = new NextResponse(null, { status: 204 });
    applyRateLimitHeaders(response.headers, rateLimitResult);
    return response;
  } catch (err) {
    const { body, status } = formatErrorResponse(err);
    return NextResponse.json(body, { status });
  }
}
