import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { connectDB } from '@/lib/db';
import { Scan } from '@/models/scan';
import { scanIdParamSchema } from '@/lib/schemas';
import { formatErrorResponse, ValidationError, NotFoundError } from '@/lib/errors';

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
