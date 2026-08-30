import { NextResponse } from 'next/server';
import { randomUUID } from 'crypto';
import { cookies } from 'next/headers';
import { getGitHubAppAuthUrl } from '@/lib/github';
import { checkRateLimit, RATE_LIMITS, applyRateLimitHeaders } from '@/lib/rate-limit';
import { formatErrorResponse, RateLimitError } from '@/lib/errors';
import { logger } from '@/lib/logger';
import { headers } from 'next/headers';

/**
 * GET /api/v1/auth/github
 *
 * Initiates the GitHub App authorization flow.
 * Generates a CSRF state parameter, stores it in a short-lived cookie,
 * and redirects the user to GitHub's authorization page.
 */
export async function GET(): Promise<NextResponse> {
  try {
    // Rate limiting
    const headersList = await headers();
    const ip = headersList.get('x-forwarded-for')?.split(',')[0]?.trim() ?? 'unknown';
    const rateLimitResult = checkRateLimit(`auth:${ip}`, RATE_LIMITS.auth);

    if (!rateLimitResult.allowed) {
      const error = new RateLimitError(rateLimitResult.retryAfterSeconds ?? 60);
      const { body, status } = formatErrorResponse(error);
      const response = NextResponse.json(body, { status });
      applyRateLimitHeaders(response.headers, rateLimitResult);
      return response;
    }

    // Generate CSRF state
    const state = randomUUID();

    // Store state in a short-lived cookie for validation in callback
    const cookieStore = await cookies();
    cookieStore.set('oauth_state', state, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      path: '/',
      maxAge: 600, // 10 minutes
    });

    // Redirect to GitHub
    const authUrl = getGitHubAppAuthUrl(state);
    logger.info('GitHub OAuth flow initiated');

    return NextResponse.redirect(authUrl);
  } catch (err) {
    logger.error({ err }, 'GitHub OAuth initiation failed');
    const { body, status } = formatErrorResponse(err);
    return NextResponse.json(body, { status });
  }
}
