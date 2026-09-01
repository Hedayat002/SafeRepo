/**
 * In-memory sliding window rate limiter.
 *
 * WARNING: MVP LIMITATION
 * This in-memory rate limiter works for a single-instance local development
 * environment only. It does NOT persist across server restarts, does NOT share
 * state across multiple instances, and is NOT suitable for distributed/production
 * deployment. A distributed rate limiting solution should be evaluated in
 * Phase 08 (Production Hardening).
 *
 * No Redis — per approved stack exclusions.
 */

interface RateLimitEntry {
  count: number;
  resetAt: number;
}

const store = new Map<string, RateLimitEntry>();

// Periodic cleanup of expired entries to prevent memory leak
const CLEANUP_INTERVAL_MS = 60_000;
let cleanupTimer: ReturnType<typeof setInterval> | null = null;

function startCleanup(): void {
  if (cleanupTimer) return;
  cleanupTimer = setInterval(() => {
    const now = Date.now();
    store.forEach((entry, key) => {
      if (entry.resetAt <= now) {
        store.delete(key);
      }
    });
  }, CLEANUP_INTERVAL_MS);
  // Allow Node.js to exit even if timer is active
  if (cleanupTimer && typeof cleanupTimer === 'object' && 'unref' in cleanupTimer) {
    cleanupTimer.unref();
  }
}

export interface RateLimitConfig {
  /** Maximum requests allowed in the window */
  maxRequests: number;
  /** Window duration in milliseconds */
  windowMs: number;
}

export interface RateLimitResult {
  allowed: boolean;
  limit: number;
  remaining: number;
  resetAt: number;
  retryAfterSeconds?: number;
}

/**
 * Check rate limit for a given key (typically IP address).
 */
export function checkRateLimit(
  key: string,
  config: RateLimitConfig
): RateLimitResult {
  startCleanup();

  const now = Date.now();
  const entry = store.get(key);

  // No existing entry or window expired — allow and start new window
  if (!entry || entry.resetAt <= now) {
    const resetAt = now + config.windowMs;
    store.set(key, { count: 1, resetAt });
    return {
      allowed: true,
      limit: config.maxRequests,
      remaining: config.maxRequests - 1,
      resetAt,
    };
  }

  // Within existing window
  entry.count += 1;

  if (entry.count > config.maxRequests) {
    const retryAfterSeconds = Math.ceil((entry.resetAt - now) / 1000);
    return {
      allowed: false,
      limit: config.maxRequests,
      remaining: 0,
      resetAt: entry.resetAt,
      retryAfterSeconds,
    };
  }

  return {
    allowed: true,
    limit: config.maxRequests,
    remaining: config.maxRequests - entry.count,
    resetAt: entry.resetAt,
  };
}

/** Rate limit configs for different endpoint types */
export const RATE_LIMITS = {
  /** Auth endpoints: 100 requests / 15 minutes per IP */
  auth: { maxRequests: 100, windowMs: 15 * 60 * 1000 } satisfies RateLimitConfig,
  /** Authenticated API routes: 1000 requests / 15 minutes per IP */
  api: { maxRequests: 1000, windowMs: 15 * 60 * 1000 } satisfies RateLimitConfig,
  /** Scan creation: 10 requests / 1 minute per IP/user */
  scans: { maxRequests: 10, windowMs: 60 * 1000 } satisfies RateLimitConfig,
} as const;

/**
 * Apply rate limit headers to a Response.
 */
export function applyRateLimitHeaders(
  headers: Headers,
  result: RateLimitResult
): void {
  headers.set('X-RateLimit-Limit', String(result.limit));
  headers.set('X-RateLimit-Remaining', String(result.remaining));
  headers.set(
    'X-RateLimit-Reset',
    String(Math.ceil(result.resetAt / 1000))
  );
  if (!result.allowed && result.retryAfterSeconds !== undefined) {
    headers.set('Retry-After', String(result.retryAfterSeconds));
  }
}

/**
 * Reset the rate limit store. For testing only.
 */
export function _resetStore(): void {
  store.clear();
}
