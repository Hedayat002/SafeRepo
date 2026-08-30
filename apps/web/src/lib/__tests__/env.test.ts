import { describe, it, expect } from 'vitest';

/**
 * Environment validation tests.
 *
 * Note: The env module uses test defaults when NODE_ENV=test,
 * so we test the Zod schema directly.
 */

import { z } from 'zod';

// Replicate the schema from env.ts for isolated testing
const envSchema = z.object({
  MONGODB_URI: z
    .string()
    .min(1, 'MONGODB_URI is required')
    .startsWith('mongodb', 'MONGODB_URI must be a valid MongoDB connection string'),
  GITHUB_APP_ID: z.string().min(1, 'GITHUB_APP_ID is required'),
  GITHUB_CLIENT_ID: z.string().min(1, 'GITHUB_CLIENT_ID is required'),
  GITHUB_CLIENT_SECRET: z.string().min(1, 'GITHUB_CLIENT_SECRET is required'),
  SESSION_SECRET: z
    .string()
    .min(32, 'SESSION_SECRET must be at least 32 characters'),
  NEXT_PUBLIC_APP_URL: z
    .string()
    .url('NEXT_PUBLIC_APP_URL must be a valid URL'),
  ALLOWED_ORIGINS: z.string().min(1, 'ALLOWED_ORIGINS is required'),
  SESSION_MAX_AGE_MS: z.coerce.number().positive().default(86_400_000),
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
});

describe('Environment Validation', () => {
  const validEnv = {
    MONGODB_URI: 'mongodb://localhost:27017/saferepo',
    GITHUB_APP_ID: 'app-123',
    GITHUB_CLIENT_ID: 'client-123',
    GITHUB_CLIENT_SECRET: 'secret-456',
    SESSION_SECRET: 'a-very-long-session-secret-that-is-at-least-32-characters',
    NEXT_PUBLIC_APP_URL: 'http://localhost:3000',
    ALLOWED_ORIGINS: 'http://localhost:3000',
  };

  it('should accept valid environment configuration', () => {
    const result = envSchema.safeParse(validEnv);
    expect(result.success).toBe(true);
  });

  it('should set default SESSION_MAX_AGE_MS to 24 hours', () => {
    const result = envSchema.parse(validEnv);
    expect(result.SESSION_MAX_AGE_MS).toBe(86_400_000);
  });

  it('should set default NODE_ENV to development', () => {
    const result = envSchema.parse(validEnv);
    expect(result.NODE_ENV).toBe('development');
  });

  it('should reject missing MONGODB_URI', () => {
    const { MONGODB_URI: _, ...rest } = validEnv;
    void _;
    const result = envSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('should reject invalid MONGODB_URI', () => {
    const result = envSchema.safeParse({ ...validEnv, MONGODB_URI: 'not-a-mongo-uri' });
    expect(result.success).toBe(false);
  });

  it('should reject missing GITHUB_CLIENT_ID', () => {
    const { GITHUB_CLIENT_ID: _, ...rest } = validEnv;
    void _;
    const result = envSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('should reject missing GITHUB_CLIENT_SECRET', () => {
    const { GITHUB_CLIENT_SECRET: _, ...rest } = validEnv;
    void _;
    const result = envSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('should reject short SESSION_SECRET', () => {
    const result = envSchema.safeParse({ ...validEnv, SESSION_SECRET: 'tooshort' });
    expect(result.success).toBe(false);
  });

  it('should reject invalid NEXT_PUBLIC_APP_URL', () => {
    const result = envSchema.safeParse({ ...validEnv, NEXT_PUBLIC_APP_URL: 'not-a-url' });
    expect(result.success).toBe(false);
  });

  it('should reject missing ALLOWED_ORIGINS', () => {
    const { ALLOWED_ORIGINS: _, ...rest } = validEnv;
    void _;
    const result = envSchema.safeParse(rest);
    expect(result.success).toBe(false);
  });

  it('should reject invalid NODE_ENV', () => {
    const result = envSchema.safeParse({ ...validEnv, NODE_ENV: 'staging' });
    expect(result.success).toBe(false);
  });

  it('should accept custom SESSION_MAX_AGE_MS', () => {
    const result = envSchema.parse({ ...validEnv, SESSION_MAX_AGE_MS: '3600000' });
    expect(result.SESSION_MAX_AGE_MS).toBe(3_600_000);
  });
});
