/**
 * Shared TypeScript types for SafeRepo.
 * All types used across multiple modules are defined here.
 */

/** GitHub user profile returned from GitHub API */
export interface GitHubUserProfile {
  id: number;
  login: string;
  name: string | null;
  email: string | null;
  avatar_url: string;
}

/** GitHub repository metadata returned from GitHub API */
export interface GitHubRepository {
  id: number;
  name: string;
  full_name: string;
  owner: {
    login: string;
    avatar_url: string;
  };
  private: boolean;
  html_url: string;
  description: string | null;
  fork: boolean;
  language: string | null;
  default_branch: string;
  stargazers_count: number;
  forks_count: number;
  open_issues_count: number;
  created_at: string;
  updated_at: string;
  pushed_at: string;
}

/** Authenticated user returned to the client (no sensitive fields) */
export interface AuthenticatedUser {
  id: string;
  username: string;
  displayName: string | null;
  avatarUrl: string | null;
}

/** Session data returned from session lookup (internal use) */
export interface SessionData {
  sessionId: string;
  userId: string;
  githubAccessToken: string;
  expiresAt: Date;
}

/** Standard API error response */
export interface ApiErrorResponse {
  error: {
    code: string;
    message: string;
    details?: unknown[];
  };
}

/** Standard paginated API response */
export interface PaginatedResponse<T> {
  data: T[];
  meta: {
    total: number;
    page: number;
    limit: number;
    pages: number;
  };
}

/** Health check response */
export interface HealthResponse {
  status: 'ok' | 'error';
  db: 'connected' | 'disconnected';
  timestamp: string;
}
