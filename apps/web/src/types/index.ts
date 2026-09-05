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

/** Finding severity levels */
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

/** Finding vulnerability categories */
export type FindingCategory =
  | 'sast'
  | 'dependency'
  | 'secret'
  | 'configuration'
  | 'license';

/** Approved scanner identifiers */
export type FindingScanner =
  | 'semgrep'
  | 'trivy'
  | 'gitleaks'
  | 'osv'
  | 'npm-audit'
  | 'pip-audit';

/** User-facing finding structure */
export interface FindingResponseData {
  id: string;
  scanId: string;
  scanner: FindingScanner;
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  file: string;
  line: number;
  endLine?: number;
  column?: number;
  endColumn?: number;
  codeSnippet?: string;
  package?: string;
  packageVersion?: string;
  fixedVersion?: string;
  vulnerabilityId: string;
  remediation?: string;
  fingerprint: string;
  metadata?: Record<string, unknown>;
  createdAt: string;
}

/** Raw Semgrep finding structure from JSON output */
export interface SemgrepRawMatch {
  check_id: string;
  path: string;
  start: {
    line: number;
    col: number;
    offset: number;
  };
  end: {
    line: number;
    col: number;
    offset: number;
  };
  extra: {
    message: string;
    severity: string;
    metadata?: {
      cwe?: string[] | string;
      owasp?: string[] | string;
      category?: string;
      confidence?: string;
      impact?: string;
      likelihood?: string;
      references?: string[];
      technology?: string[];
      subcategory?: string[];
      [key: string]: unknown;
    };
    lines?: string;
    fix?: string;
    [key: string]: unknown;
  };
}

/** Raw Semgrep JSON output root structure */
export interface SemgrepRawOutput {
  results: SemgrepRawMatch[];
  errors?: Array<{
    code: number;
    level: string;
    type: string;
    message: string;
    path?: string;
  }>;
  paths?: {
    scanned?: string[];
    skipped?: Array<{
      path: string;
      reason: string;
    }>;
  };
  version?: string;
}

/** Supported dependency ecosystems */
export type DependencyEcosystem = 'npm' | 'pypi';

/** Static dependency coordinate extracted from repository manifests */
export interface DependencyCoordinate {
  name: string;
  version: string;
  ecosystem: DependencyEcosystem;
  manifestPath: string;
}

/** Result of static ecosystem and manifest detection */
export interface EcosystemDetectionResult {
  hasNode: boolean;
  hasPython: boolean;
  coordinates: DependencyCoordinate[];
  manifests: {
    node: string[];
    python: string[];
  };
}

/** Raw Gitleaks finding structure from JSON report output */
export interface GitleaksRawFinding {
  Description?: string;
  StartLine?: number;
  EndLine?: number;
  StartColumn?: number;
  EndColumn?: number;
  Match?: string;
  Secret?: string;
  File?: string;
  SymlinkFile?: string;
  Commit?: string;
  Entropy?: number;
  Author?: string;
  Email?: string;
  Date?: string;
  Message?: string;
  Tags?: string[];
  RuleID?: string;
  Fingerprint?: string;
  [key: string]: unknown;
}

/** Normalized Gitleaks finding structure (strictly redacted) */
export interface GitleaksSecretFinding {
  ruleId: string;
  secretType: string;
  file: string;
  line: number;
  endLine?: number;
  column?: number;
  endColumn?: number;
  severity: FindingSeverity;
  title: string;
  description: string;
  codeSnippet: string;
  remediation: string;
  fingerprint: string;
  metadata: {
    ruleId: string;
    secretType: string;
    entropy?: number;
    commit?: string;
    author?: string;
    date?: string;
    tags?: string[];
    scanners: string[];
    [key: string]: unknown;
  };
}

/** Discriminated union for scanner execution results */
export interface BaseScannerResult {
  scanner: FindingScanner;
}

export interface ScannerSuccessResult<T = unknown> extends BaseScannerResult {
  status: 'success';
  findings: T[];
  durationMs: number;
  rawMatchesCount: number;
}

export interface ScannerUnavailableResult extends BaseScannerResult {
  status: 'unavailable';
  scanner: 'trivy' | 'gitleaks';
  reason: string;
}

export interface ScannerFailedResult extends BaseScannerResult {
  status: 'failed';
  error: string;
  durationMs?: number;
}

export type ScannerResult<T = unknown> =
  | ScannerSuccessResult<T>
  | ScannerUnavailableResult
  | ScannerFailedResult;


