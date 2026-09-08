import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { getRepo } from '@/lib/github';
import { connectDB } from '@/lib/db';
import { Scan } from '@/models/scan';
import { createScanSchema, scansQuerySchema } from '@/lib/schemas';
import { formatErrorResponse, ValidationError, NotFoundError } from '@/lib/errors';
import { checkRateLimit, RATE_LIMITS, applyRateLimitHeaders } from '@/lib/rate-limit';
import { env } from '@/lib/env';

import { enqueueScanJob } from '@/lib/scanner/queue';

/**
 * POST /api/v1/scans
 *
 * Requests a new scan for a repository.
 * - Requires authentication.
 * - Validates input parameters with Zod.
 * - Verifies repository access with user's GitHub token.
 * - Checks repository size limit against metadata.
 * - Creates scan record with status "queued" via in-database queue.
 * - The trusted worker process polls the MongoDB queue and claims jobs
 *   via atomic findOneAndUpdate. No in-process fire-and-forget dispatch.
 */
export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Rate limit
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
    const rateLimitResult = checkRateLimit(`scan:${ip}`, RATE_LIMITS.scans);

    if (!rateLimitResult.allowed) {
      const response = NextResponse.json(
        { error: { code: 'RATE_LIMITED', message: 'Too many scan requests' } },
        { status: 429 }
      );
      applyRateLimitHeaders(response.headers, rateLimitResult);
      return response;
    }

    // Require authentication
    const { user, githubAccessToken } = await requireAuth();

    // Parse and validate body
    const body = await request.json().catch(() => null);
    const parseResult = createScanSchema.safeParse(body);

    if (!parseResult.success) {
      throw new ValidationError('Invalid scan request payload', parseResult.error.issues);
    }

    const { repositoryOwner, repositoryName } = parseResult.data;

    // Verify user has access to repository on GitHub
    const repoMeta = await getRepo(githubAccessToken, repositoryOwner, repositoryName);
    if (!repoMeta) {
      throw new NotFoundError(`Repository ${repositoryOwner}/${repositoryName} not found or access denied`);
    }

    const branch = parseResult.data.branch || repoMeta.default_branch || 'main';

    // Pre-flight check: GitHub reports repository size in KB
    // Reject if reported size exceeds configured limit
    const reportedSizeMb = (repoMeta as { size?: number }).size ? (repoMeta as { size?: number }).size! / 1024 : 0;
    if (reportedSizeMb > env.MAX_REPO_SIZE_MB) {
      throw new ValidationError(
        `Repository size (${reportedSizeMb.toFixed(1)} MB) exceeds maximum allowed size of ${env.MAX_REPO_SIZE_MB} MB`
      );
    }

    await connectDB();

    // Create Scan document in queued status via queue manager.
    // Phase 06: The trusted worker process polls this queue and claims jobs
    // via atomic findOneAndUpdate. No in-process fire-and-forget dispatch.
    const scan = await enqueueScanJob({
      userId: user._id,
      repositoryOwner,
      repositoryName,
      repositoryUrl: repoMeta.html_url,
      branch,
    });

    const response = NextResponse.json(
      {
        data: {
          id: scan._id.toString(),
          repositoryOwner: scan.repositoryOwner,
          repositoryName: scan.repositoryName,
          repositoryUrl: scan.repositoryUrl,
          branch: scan.branch,
          status: scan.status,
          scanners: scan.scanners,
          summary: scan.summary,
          createdAt: scan.createdAt,
          updatedAt: scan.updatedAt,
        },
      },
      { status: 201 }
    );

    applyRateLimitHeaders(response.headers, rateLimitResult);
    return response;
  } catch (err) {
    const { body, status } = formatErrorResponse(err);
    return NextResponse.json(body, { status });
  }
}

/**
 * GET /api/v1/scans
 *
 * Lists scan history for the authenticated user (paginated).
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    const { user } = await requireAuth();

    const searchParams = Object.fromEntries(request.nextUrl.searchParams);
    const parseResult = scansQuerySchema.safeParse(searchParams);

    if (!parseResult.success) {
      throw new ValidationError('Invalid query parameters', parseResult.error.issues);
    }

    const { page, per_page, status } = parseResult.data;

    await connectDB();

    const query: Record<string, unknown> = { userId: user._id };
    if (status) {
      query.status = status;
    }

    const skip = (page - 1) * per_page;

    const [scans, totalCount] = await Promise.all([
      Scan.find(query)
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(per_page)
        .lean(),
      Scan.countDocuments(query),
    ]);

    return NextResponse.json({
      data: scans.map((s) => ({
        id: s._id.toString(),
        repositoryOwner: s.repositoryOwner,
        repositoryName: s.repositoryName,
        repositoryUrl: s.repositoryUrl,
        branch: s.branch,
        commitSha: s.commitSha,
        status: s.status,
        scanners: s.scanners,
        summary: s.summary,
        error: s.error,
        startedAt: s.startedAt,
        completedAt: s.completedAt,
        duration: s.duration,
        createdAt: s.createdAt,
        updatedAt: s.updatedAt,
      })),
      meta: {
        total: totalCount,
        page,
        limit: per_page,
        pages: Math.ceil(totalCount / per_page),
      },
    });
  } catch (err) {
    const { body, status } = formatErrorResponse(err);
    return NextResponse.json(body, { status });
  }
}
