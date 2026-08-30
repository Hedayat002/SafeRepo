import { NextResponse } from 'next/server';
import { requireAuth } from '@/lib/auth';
import { getRepo } from '@/lib/github';
import { repoParamsSchema } from '@/lib/schemas';
import { formatErrorResponse, ValidationError, NotFoundError } from '@/lib/errors';
import { checkRateLimit, RATE_LIMITS, applyRateLimitHeaders } from '@/lib/rate-limit';

/**
 * GET /api/v1/repos/:owner/:name
 *
 * Fetches metadata for a specific repository from GitHub API.
 * Requires authentication. Zod-validated path params.
 */
export async function GET(
  request: Request,
  { params }: { params: Promise<{ owner: string; name: string }> }
): Promise<NextResponse> {
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

    // Validate path params
    const { owner, name } = await params;
    const parseResult = repoParamsSchema.safeParse({ owner, name });

    if (!parseResult.success) {
      throw new ValidationError('Invalid path parameters', parseResult.error.issues);
    }

    // Fetch repo from GitHub API (server-side)
    const repo = await getRepo(githubAccessToken, owner, name);

    if (!repo) {
      throw new NotFoundError(`Repository ${owner}/${name} not found or not accessible`);
    }

    const response = NextResponse.json({
      data: {
        id: repo.id,
        name: repo.name,
        fullName: repo.full_name,
        owner: repo.owner.login,
        ownerAvatarUrl: repo.owner.avatar_url,
        private: repo.private,
        htmlUrl: repo.html_url,
        description: repo.description,
        fork: repo.fork,
        language: repo.language,
        defaultBranch: repo.default_branch,
        stargazersCount: repo.stargazers_count,
        forksCount: repo.forks_count,
        openIssuesCount: repo.open_issues_count,
        createdAt: repo.created_at,
        updatedAt: repo.updated_at,
        pushedAt: repo.pushed_at,
      },
    });

    applyRateLimitHeaders(response.headers, rateLimitResult);
    return response;
  } catch (err) {
    const { body, status } = formatErrorResponse(err);
    return NextResponse.json(body, { status });
  }
}
