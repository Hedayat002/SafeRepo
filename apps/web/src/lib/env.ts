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
