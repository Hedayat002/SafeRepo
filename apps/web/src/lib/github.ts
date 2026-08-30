import { logger } from '@/lib/logger';
import type { GitHubUserProfile, GitHubRepository } from '@/types';

/**
 * GitHub App API helpers.
 *
 * All interactions with GitHub happen server-side.
 * GitHub credentials/tokens never reach the browser.
 *
 * Uses Node.js built-in fetch — no external HTTP client library.
 *
 * GitHub App Minimum Permissions Required:
 * - Repository metadata: Read-only (list repos, fetch metadata)
 * - Account (user profile): Read-only (username, avatar, email)
 */

const GITHUB_API_BASE = 'https://api.github.com';
const GITHUB_AUTH_BASE = 'https://github.com';

/**
 * Construct the GitHub App authorization URL.
 * Redirects the user to GitHub to authorize the SafeRepo GitHub App.
 */
export function getGitHubAppAuthUrl(state: string): string {
  const clientId = process.env.GITHUB_CLIENT_ID;

  if (!clientId) {
    throw new Error('GITHUB_CLIENT_ID is not configured');
  }

  const redirectUri = `${process.env.NEXT_PUBLIC_APP_URL}/api/v1/auth/github/callback`;

  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    scope: 'read:user user:email',
  });

  return `${GITHUB_AUTH_BASE}/login/oauth/authorize?${params.toString()}`;
}

/**
 * Exchange an authorization code for a user access token.
 * Server-side only — client secret never exposed.
 */
export async function exchangeCodeForToken(code: string): Promise<string> {
  const response = await fetch(`${GITHUB_AUTH_BASE}/login/oauth/access_token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify({
      client_id: process.env.GITHUB_CLIENT_ID,
      client_secret: process.env.GITHUB_CLIENT_SECRET,
      code,
    }),
  });

  if (!response.ok) {
    logger.error({ status: response.status }, 'GitHub token exchange failed');
    throw new Error('Failed to exchange authorization code for token');
  }

  const data = (await response.json()) as { access_token?: string; error?: string };

  if (data.error || !data.access_token) {
    logger.error({ error: data.error }, 'GitHub token exchange returned error');
    throw new Error(`GitHub OAuth error: ${data.error ?? 'No access token returned'}`);
  }

  return data.access_token;
}

/**
 * Fetch the authenticated user's GitHub profile.
 * Server-side only.
 */
export async function getGitHubUser(accessToken: string): Promise<GitHubUserProfile> {
  const response = await fetch(`${GITHUB_API_BASE}/user`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  if (!response.ok) {
    logger.error({ status: response.status }, 'GitHub user fetch failed');
    throw new Error('Failed to fetch GitHub user profile');
  }

  const data = (await response.json()) as GitHubUserProfile;
  return data;
}

/**
 * Fetch repositories accessible to the authenticated user.
 * Uses the user's access token via the GitHub App installation.
 * Server-side only.
 */
export async function getUserRepos(
  accessToken: string,
  page: number,
  perPage: number
): Promise<{ repos: GitHubRepository[]; totalCount: number }> {
  const params = new URLSearchParams({
    page: String(page),
    per_page: String(perPage),
    sort: 'updated',
    direction: 'desc',
  });

  const response = await fetch(`${GITHUB_API_BASE}/user/repos?${params.toString()}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  if (!response.ok) {
    logger.error({ status: response.status }, 'GitHub repos fetch failed');
    throw new Error('Failed to fetch GitHub repositories');
  }

  const repos = (await response.json()) as GitHubRepository[];

  // GitHub returns total count in Link header; parse if available
  const linkHeader = response.headers.get('link');
  let totalCount = repos.length;

  if (linkHeader) {
    const lastMatch = linkHeader.match(/page=(\d+)>;\s*rel="last"/);
    if (lastMatch) {
      totalCount = parseInt(lastMatch[1], 10) * perPage;
    }
  }

  return { repos, totalCount };
}

/**
 * Fetch metadata for a specific repository.
 * Server-side only.
 */
export async function getRepo(
  accessToken: string,
  owner: string,
  name: string
): Promise<GitHubRepository | null> {
  const response = await fetch(`${GITHUB_API_BASE}/repos/${owner}/${name}`, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/vnd.github+json',
      'X-GitHub-Api-Version': '2022-11-28',
    },
  });

  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    logger.error({ status: response.status, owner, name }, 'GitHub repo fetch failed');
    throw new Error('Failed to fetch GitHub repository');
  }

  return (await response.json()) as GitHubRepository;
}
