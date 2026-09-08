import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { connectDB } from '@/lib/db';
import { Scan } from '@/models/scan';
import { Finding } from '@/models/finding';
import { scanIdParamSchema, findingsQuerySchema } from '@/lib/schemas';
import { formatErrorResponse, ValidationError, NotFoundError } from '@/lib/errors';
import { checkRateLimit, applyRateLimitHeaders } from '@/lib/rate-limit';

/**
 * GET /api/v1/scans/:id/findings
 *
 * Retrieves normalized security findings for a specific scan.
 * - Requires authentication.
 * - Validates scanId path parameter and query filters.
 * - Enforces user authorization (users can only access findings for their own scans).
 * - Supports pagination (page, per_page) and filtering (severity, category, scanner).
 */
export async function GET(
  request: NextRequest,
  context: { params: Promise<{ id: string }> }
): Promise<NextResponse> {
  try {
    const { user } = await requireAuth();

    // Rate limit: 100 requests per minute per user
    const rateLimitResult = checkRateLimit(`findings:${user._id.toString()}`, {
      maxRequests: 100,
      windowMs: 60 * 1000,
    });

    if (!rateLimitResult.allowed) {
      const response = NextResponse.json(
        {
          error: {
            code: 'RATE_LIMIT_EXCEEDED',
            message: 'Findings query rate limit exceeded. Please retry later.',
          },
        },
        { status: 429 }
      );
      applyRateLimitHeaders(response.headers, rateLimitResult);
      return response;
    }

    const params = await context.params;

    // Validate path parameter
    const paramResult = scanIdParamSchema.safeParse(params);
    if (!paramResult.success) {
      throw new ValidationError('Invalid scan ID parameter', paramResult.error.issues);
    }

    const { id } = paramResult.data;

    // Validate query parameters
    const searchParams = Object.fromEntries(request.nextUrl.searchParams);
    const queryResult = findingsQuerySchema.safeParse(searchParams);

    if (!queryResult.success) {
      throw new ValidationError('Invalid findings query parameters', queryResult.error.issues);
    }

    const { page, per_page, severity, category, scanner } = queryResult.data;

    await connectDB();

    // Verify scan ownership (anti-enumeration)
    const scan = await Scan.findOne({ _id: id, userId: user._id }).lean();
    if (!scan) {
      throw new NotFoundError(`Scan ${id} not found`);
    }

    // Build filter query
    const filter: Record<string, unknown> = { scanId: id };
    if (severity) {
      filter.severity = severity;
    }
    if (category) {
      filter.category = category;
    }
    if (scanner) {
      filter.scanner = scanner;
    }

    const skip = (page - 1) * per_page;

    const [findings, totalCount] = await Promise.all([
      Finding.find(filter)
        .sort({ severity: 1, file: 1, line: 1 })
        .skip(skip)
        .limit(per_page)
        .lean(),
      Finding.countDocuments(filter),
    ]);

    const response = NextResponse.json({
      data: findings.map((f) => ({
        id: f._id.toString(),
        scanId: f.scanId.toString(),
        scanner: f.scanner,
        category: f.category,
        severity: f.severity,
        title: f.title,
        description: f.description,
        file: f.file,
        line: f.line,
        endLine: f.endLine,
        column: f.column,
        endColumn: f.endColumn,
        codeSnippet: f.codeSnippet,
        package: f.package,
        packageVersion: f.packageVersion,
        fixedVersion: f.fixedVersion,
        vulnerabilityId: f.vulnerabilityId,
        remediation: f.remediation,
        fingerprint: f.fingerprint,
        metadata: f.metadata,
        createdAt: f.createdAt,
      })),
      meta: {
        total: totalCount,
        page,
        limit: per_page,
        pages: Math.ceil(totalCount / per_page),
      },
    });

    applyRateLimitHeaders(response.headers, rateLimitResult);
    return response;
  } catch (err) {
    const { body, status } = formatErrorResponse(err);
    return NextResponse.json(body, { status });
  }
}
