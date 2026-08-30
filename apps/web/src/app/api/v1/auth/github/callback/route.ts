import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import { oauthCallbackSchema } from '@/lib/schemas';
import { exchangeCodeForToken, getGitHubUser } from '@/lib/github';
import { createSession, setSessionCookie } from '@/lib/session';
import { User } from '@/models/user';
import { connectDB } from '@/lib/db';
import { logger } from '@/lib/logger';

/**
 * GET /api/v1/auth/github/callback
 *
 * GitHub App OAuth callback handler.
 * 1. Validates CSRF state parameter
 * 2. Exchanges authorization code for access token (server-side)
 * 3. Fetches GitHub user profile (server-side)
 * 4. Creates or updates User document in MongoDB
 * 5. Creates server-side Session in MongoDB
 * 6. Sets HttpOnly session cookie
 * 7. Redirects to /dashboard
 */
export async function GET(request: NextRequest): Promise<NextResponse> {
  const appUrl = process.env.NEXT_PUBLIC_APP_URL ?? 'http://localhost:3000';

  try {
    // Parse and validate query params
    const searchParams = Object.fromEntries(request.nextUrl.searchParams);
    const parseResult = oauthCallbackSchema.safeParse(searchParams);

    if (!parseResult.success) {
      logger.warn('OAuth callback received invalid parameters');
      return NextResponse.redirect(`${appUrl}/login?error=invalid_request`);
    }

    const { code, state } = parseResult.data;

    // Validate CSRF state against stored cookie
    const cookieStore = await cookies();
    const storedState = cookieStore.get('oauth_state')?.value;

    if (!storedState || storedState !== state) {
      logger.warn('OAuth state mismatch — possible CSRF attempt');
      return NextResponse.redirect(`${appUrl}/login?error=state_mismatch`);
    }

    // Clear the state cookie
    cookieStore.set('oauth_state', '', { maxAge: 0, path: '/' });

    // Exchange code for access token (server-side)
    const accessToken = await exchangeCodeForToken(code);

    // Fetch GitHub user profile (server-side)
    const githubUser = await getGitHubUser(accessToken);

    // Create or update user in MongoDB
    await connectDB();
    const user = await User.findOneAndUpdate(
      { githubId: String(githubUser.id) },
      {
        githubId: String(githubUser.id),
        username: githubUser.login,
        displayName: githubUser.name,
        email: githubUser.email,
        avatarUrl: githubUser.avatar_url,
      },
      { upsert: true, new: true, runValidators: true }
    );

    // Create server-side session
    const sessionId = await createSession(
      user._id.toString(),
      accessToken
    );

    // Set HttpOnly session cookie
    await setSessionCookie(sessionId);

    logger.info({ userId: user._id, username: user.username }, 'User authenticated via GitHub');

    return NextResponse.redirect(`${appUrl}/dashboard`);
  } catch (err) {
    logger.error({ err }, 'OAuth callback failed');
    return NextResponse.redirect(`${appUrl}/login?error=auth_failed`);
  }
}
