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

/** Scan lifecycle statuses */
export type ScanStatus =
  | 'queued'
  | 'cloning'
  | 'scanning'
  | 'normalizing'
  | 'completed'
  | 'failed'
  | 'timed_out';

/** Finding severity summary */
export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/** User-facing scan metadata */
export interface ScanResponseData {
  id: string;
  userId: string;
  repositoryOwner: string;
  repositoryName: string;
  repositoryUrl: string;
  branch: string;
  commitSha: string | null;
  status: ScanStatus;
  scanners: string[];
  summary: ScanSummary;
  error: string | null;
  startedAt: string | null;
  completedAt: string | null;
  duration: number | null;
  createdAt: string;
  updatedAt: string;
}

/** Input for initiating a scan */
export interface CreateScanInput {
  repositoryOwner: string;
  repositoryName: string;
  branch?: string;
}
