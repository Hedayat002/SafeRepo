import { NextRequest, NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { getUserRepos } from '@/lib/github';
import { reposQuerySchema } from '@/lib/schemas';
import { formatErrorResponse, ValidationError } from '@/lib/errors';
import { checkRateLimit, RATE_LIMITS, applyRateLimitHeaders } from '@/lib/rate-limit';

/**
 * GET /api/v1/repos
 *
 * Lists GitHub repositories accessible to the authenticated user.
 * Proxies to GitHub API using the stored access token (server-side).
 * Requires authentication. Zod-validated query params.
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    // Rate limiting
    const ip = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
    const rateLimitResult = checkRateLimit(`api:${ip}`, RATE_LIMITS.api);

    if (!rateLimitResult.allowed) {
      const response = NextResponse.json(
        { error: { code: 'RATE_LIMITED', message: 'Too many requests' } },
        { status: 429 }
      );
      applyRateLimitHeaders(response.headers, rateLimitResult);
      return response;
    }

    // Authentication
    const { githubAccessToken } = await requireAuth();

    // Validate query params
    const searchParams = Object.fromEntries(request.nextUrl.searchParams);
    const parseResult = reposQuerySchema.safeParse(searchParams);

    if (!parseResult.success) {
      throw new ValidationError('Invalid query parameters', parseResult.error.issues);
    }

    const { page, per_page } = parseResult.data;

    // Fetch repos from GitHub API (server-side)
    const { repos, totalCount } = await getUserRepos(githubAccessToken, page, per_page);

    const response = NextResponse.json({
      data: repos.map((repo) => ({
        id: repo.id,
        name: repo.name,
        fullName: repo.full_name,
        owner: repo.owner.login,
        private: repo.private,
        htmlUrl: repo.html_url,
        description: repo.description,
        language: repo.language,
        defaultBranch: repo.default_branch,
        stargazersCount: repo.stargazers_count,
        forksCount: repo.forks_count,
        updatedAt: repo.updated_at,
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
