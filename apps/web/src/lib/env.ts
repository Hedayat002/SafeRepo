import { z } from 'zod';

/**
 * Environment variable validation using Zod.
 *
 * Fails fast at import time if required variables are missing or invalid.
 * Never contains real secrets — only reads from process.env.
 */

const envSchema = z.object({
  // MongoDB
  MONGODB_URI: z
    .string()
    .min(1, 'MONGODB_URI is required')
    .startsWith('mongodb', 'MONGODB_URI must be a valid MongoDB connection string'),

  // GitHub App
  GITHUB_APP_ID: z.string().min(1, 'GITHUB_APP_ID is required'),
  GITHUB_CLIENT_ID: z.string().min(1, 'GITHUB_CLIENT_ID is required'),
  GITHUB_CLIENT_SECRET: z.string().min(1, 'GITHUB_CLIENT_SECRET is required'),

  // Session
  SESSION_SECRET: z
    .string()
    .min(32, 'SESSION_SECRET must be at least 32 characters'),

  // Application
  NEXT_PUBLIC_APP_URL: z
    .string()
    .url('NEXT_PUBLIC_APP_URL must be a valid URL'),
  ALLOWED_ORIGINS: z.string().min(1, 'ALLOWED_ORIGINS is required'),

  // Optional
  SESSION_MAX_AGE_MS: z.coerce
    .number()
    .positive()
    .default(86_400_000), // 24 hours
  MAX_REPO_SIZE_MB: z.coerce
    .number()
    .positive()
    .default(100),
  SCAN_WORKSPACE_DIR: z.string().optional(),
  SEMGREP_IMAGE: z.string().default('semgrep/semgrep:1.100.0'),
  SEMGREP_TIMEOUT_MS: z.coerce
    .number()
    .positive()
    .default(180_000), // 180 seconds
  SEMGREP_MEMORY_LIMIT: z.string().default('512m'),
  MAX_SCANNER_STDOUT_BYTES: z.coerce
    .number()
    .positive()
    .default(10 * 1024 * 1024), // 10 MB
  // Phase 04: Trivy & OSV
  TRIVY_IMAGE: z.string().default('aquasec/trivy:0.59.1'),
  TRIVY_TIMEOUT_MS: z.coerce
    .number()
    .positive()
    .default(180_000), // 180 seconds
  TRIVY_MEMORY_LIMIT: z.string().default('512m'),
  TRIVY_DB_PATH: z.string().optional(),
  OSV_API_URL: z.string().url().default('https://api.osv.dev/v1/querybatch'),
  OSV_TIMEOUT_MS: z.coerce
    .number()
    .positive()
    .default(30_000), // 30 seconds
  // Phase 05: Gitleaks
  GITLEAKS_IMAGE: z.string().default('zricethezav/gitleaks:v8.24.0'),
  GITLEAKS_TIMEOUT_MS: z.coerce
    .number()
    .positive()
    .default(180_000), // 180 seconds
  GITLEAKS_MEMORY_LIMIT: z.string().default('512m'),
  // Phase 06: Queue & Worker
  MAX_CONCURRENT_SCANS: z.coerce
    .number()
    .int()
    .positive()
    .default(1),
  SCAN_QUEUE_POLL_INTERVAL_MS: z.coerce
    .number()
    .positive()
    .default(5_000), // 5 seconds
  SCAN_STALE_TIMEOUT_MS: z.coerce
    .number()
    .positive()
    .default(360_000), // 360 seconds (6 minutes)
  SCAN_TIMEOUT_SECONDS: z.coerce
    .number()
    .positive()
    .default(300), // 300 seconds (5 minutes)
  NODE_ENV: z
    .enum(['development', 'production', 'test'])
    .default('development'),
});

export type Env = z.infer<typeof envSchema>;

/**
 * Validated environment configuration.
 *
 * In test environment, returns safe defaults to avoid requiring
 * real env vars during unit tests.
 */
function loadEnv(): Env {
  // In test environment, use safe defaults
  if (process.env.NODE_ENV === 'test') {
    return {
      MONGODB_URI: process.env.MONGODB_URI ?? 'mongodb://localhost:27017/saferepo-test',
      GITHUB_APP_ID: process.env.GITHUB_APP_ID ?? 'test-app-id',
      GITHUB_CLIENT_ID: process.env.GITHUB_CLIENT_ID ?? 'test-client-id',
      GITHUB_CLIENT_SECRET: process.env.GITHUB_CLIENT_SECRET ?? 'test-client-secret',
      SESSION_SECRET: process.env.SESSION_SECRET ?? 'test-session-secret-that-is-at-least-32-chars',
      NEXT_PUBLIC_APP_URL: process.env.NEXT_PUBLIC_APP_URL ?? 'http://localhost:3000',
      ALLOWED_ORIGINS: process.env.ALLOWED_ORIGINS ?? 'http://localhost:3000',
      SESSION_MAX_AGE_MS: Number(process.env.SESSION_MAX_AGE_MS) || 86_400_000,
      MAX_REPO_SIZE_MB: Number(process.env.MAX_REPO_SIZE_MB) || 100,
      SCAN_WORKSPACE_DIR: process.env.SCAN_WORKSPACE_DIR,
      SEMGREP_IMAGE: process.env.SEMGREP_IMAGE ?? 'semgrep/semgrep:1.100.0',
      SEMGREP_TIMEOUT_MS: Number(process.env.SEMGREP_TIMEOUT_MS) || 180_000,
      SEMGREP_MEMORY_LIMIT: process.env.SEMGREP_MEMORY_LIMIT ?? '512m',
      MAX_SCANNER_STDOUT_BYTES: Number(process.env.MAX_SCANNER_STDOUT_BYTES) || 10 * 1024 * 1024,
      TRIVY_IMAGE: process.env.TRIVY_IMAGE ?? 'aquasec/trivy:0.59.1',
      TRIVY_TIMEOUT_MS: Number(process.env.TRIVY_TIMEOUT_MS) || 180_000,
      TRIVY_MEMORY_LIMIT: process.env.TRIVY_MEMORY_LIMIT ?? '512m',
      TRIVY_DB_PATH: process.env.TRIVY_DB_PATH,
      OSV_API_URL: process.env.OSV_API_URL ?? 'https://api.osv.dev/v1/querybatch',
      OSV_TIMEOUT_MS: Number(process.env.OSV_TIMEOUT_MS) || 30_000,
      GITLEAKS_IMAGE: process.env.GITLEAKS_IMAGE ?? 'zricethezav/gitleaks:v8.24.0',
      GITLEAKS_TIMEOUT_MS: Number(process.env.GITLEAKS_TIMEOUT_MS) || 180_000,
      GITLEAKS_MEMORY_LIMIT: process.env.GITLEAKS_MEMORY_LIMIT ?? '512m',
      MAX_CONCURRENT_SCANS: Number(process.env.MAX_CONCURRENT_SCANS) || 1,
      SCAN_QUEUE_POLL_INTERVAL_MS: Number(process.env.SCAN_QUEUE_POLL_INTERVAL_MS) || 5_000,
      SCAN_STALE_TIMEOUT_MS: Number(process.env.SCAN_STALE_TIMEOUT_MS) || 360_000,
      SCAN_TIMEOUT_SECONDS: Number(process.env.SCAN_TIMEOUT_SECONDS) || 300,
      NODE_ENV: 'test',
    };
  }

  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    const formatted = result.error.issues
      .map((issue) => `  - ${issue.path.join('.')}: ${issue.message}`)
      .join('\n');

    throw new Error(
      `Environment validation failed:\n${formatted}\n\nCopy .env.example to .env.local and fill in the required values.`
    );
  }

  return result.data;
}

export const env = loadEnv();
