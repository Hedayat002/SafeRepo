import crypto from 'crypto';
import { NextRequest, NextResponse } from 'next/server';
import { logger } from '@/lib/logger';
import { getSession, getSessionIdFromCookies } from '@/lib/session';

export const SENSITIVE_HEADERS = new Set([
  'authorization',
  'cookie',
  'set-cookie',
  'x-session-id',
  'session',
  'token',
]);

/**
 * Redacts sensitive HTTP header values to prevent credential leakage in logs.
 */
export function redactHeaders(
  headers: Headers | Record<string, string>
): Record<string, string> {
  const sanitized: Record<string, string> = {};

  if (headers instanceof Headers) {
    headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      sanitized[lowerKey] = SENSITIVE_HEADERS.has(lowerKey) ? '[REDACTED]' : value;
    });
  } else {
    for (const [key, value] of Object.entries(headers)) {
      const lowerKey = key.toLowerCase();
      sanitized[lowerKey] = SENSITIVE_HEADERS.has(lowerKey) ? '[REDACTED]' : value;
    }
  }

  return sanitized;
}

export type ApiRouteHandler<T = unknown> = (
  request: NextRequest,
  context: T
) => Promise<NextResponse> | NextResponse;

/**
 * Request logging and tracing middleware wrapper for API route handlers.
 *
 * - Generates or propagates `X-Request-Id` UUID header.
 * - Logs request metadata: method, path, status, durationMs, and userId (if authenticated).
 * - Redacts sensitive headers and ensures no secrets appear in logs.
 */
export function withRequestLogging<T = unknown>(
  handler: ApiRouteHandler<T>
): ApiRouteHandler<T> {
  return async (request: NextRequest, context: T): Promise<NextResponse> => {
    const startTime = Date.now();
    const requestId =
      request.headers.get('x-request-id') ||
      request.headers.get('x-correlation-id') ||
      crypto.randomUUID();

    const method = request.method;
    const path = request.nextUrl?.pathname || new URL(request.url).pathname;

    let userId: string | undefined;
    try {
      const sessionId = await getSessionIdFromCookies();
      if (sessionId) {
        const session = await getSession(sessionId);
        if (session?.userId) {
          userId = session.userId.toString();
        }
      }
    } catch {
      // Unauthenticated or error reading session — ignore for logging
    }

    try {
      const response = await handler(request, context);
      const durationMs = Date.now() - startTime;

      // Propagate X-Request-Id header on response
      response.headers.set('X-Request-Id', requestId);

      logger.info(
        {
          requestId,
          method,
          path,
          statusCode: response.status,
          durationMs,
          ...(userId ? { userId } : {}),
        },
        'API request completed'
      );

      return response;
    } catch (err) {
      const durationMs = Date.now() - startTime;
      logger.error(
        {
          requestId,
          method,
          path,
          durationMs,
          ...(userId ? { userId } : {}),
          err: err instanceof Error ? err.message : String(err),
        },
        'API request error'
      );
      throw err;
    }
  };
}
