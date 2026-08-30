import { describe, it, expect, beforeEach } from 'vitest';
import {
  checkRateLimit,
  _resetStore,
  type RateLimitConfig,
} from '@/lib/rate-limit';

describe('Rate Limiter', () => {
  const config: RateLimitConfig = {
    maxRequests: 3,
    windowMs: 60_000, // 1 minute
  };

  beforeEach(() => {
    _resetStore();
  });

  it('should allow requests under the limit', () => {
    const result = checkRateLimit('ip-1', config);
    expect(result.allowed).toBe(true);
    expect(result.remaining).toBe(2);
    expect(result.limit).toBe(3);
  });

  it('should decrement remaining count', () => {
    checkRateLimit('ip-2', config);
    const result = checkRateLimit('ip-2', config);
    expect(result.remaining).toBe(1);
  });

  it('should block requests over the limit', () => {
    checkRateLimit('ip-3', config);
    checkRateLimit('ip-3', config);
    checkRateLimit('ip-3', config);
    const result = checkRateLimit('ip-3', config);

    expect(result.allowed).toBe(false);
    expect(result.remaining).toBe(0);
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('should track different IPs independently', () => {
    checkRateLimit('ip-a', config);
    checkRateLimit('ip-a', config);
    checkRateLimit('ip-a', config);

    const resultA = checkRateLimit('ip-a', config);
    const resultB = checkRateLimit('ip-b', config);

    expect(resultA.allowed).toBe(false);
    expect(resultB.allowed).toBe(true);
  });

  it('should include reset timestamp', () => {
    const result = checkRateLimit('ip-4', config);
    expect(result.resetAt).toBeGreaterThan(Date.now());
  });

  it('should reset after window expires', () => {
    // Simulate window expiration by using a very short window
    const shortConfig: RateLimitConfig = { maxRequests: 1, windowMs: 1 };

    checkRateLimit('ip-5', shortConfig);

    // Wait for window to expire
    return new Promise<void>((resolve) => {
      setTimeout(() => {
        const result = checkRateLimit('ip-5', shortConfig);
        expect(result.allowed).toBe(true);
        resolve();
      }, 10);
    });
  });

  it('should return retryAfterSeconds when blocked', () => {
    checkRateLimit('ip-6', config);
    checkRateLimit('ip-6', config);
    checkRateLimit('ip-6', config);

    const result = checkRateLimit('ip-6', config);
    expect(result.retryAfterSeconds).toBeDefined();
    expect(result.retryAfterSeconds).toBeGreaterThan(0);
    expect(result.retryAfterSeconds).toBeLessThanOrEqual(60);
  });
});
