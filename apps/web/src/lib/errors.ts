/**
 * Typed error classes for SafeRepo API.
 *
 * All errors produce structured responses that never leak
 * stack traces, internal paths, or implementation details.
 */

export class AppError extends Error {
  public readonly code: string;
  public readonly statusCode: number;
  public readonly details: unknown[];

  constructor(
    message: string,
    options: {
      code?: string;
      statusCode?: number;
      details?: unknown[];
      cause?: unknown;
    } = {}
  ) {
    super(message, { cause: options.cause });
    this.name = 'AppError';
    this.code = options.code ?? 'INTERNAL_ERROR';
    this.statusCode = options.statusCode ?? 500;
    this.details = options.details ?? [];
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details: unknown[] = []) {
    super(message, {
      code: 'VALIDATION_ERROR',
      statusCode: 400,
      details,
    });
    this.name = 'ValidationError';
  }
}

export class UnauthorizedError extends AppError {
  constructor(message = 'Authentication required') {
    super(message, {
      code: 'UNAUTHORIZED',
      statusCode: 401,
    });
    this.name = 'UnauthorizedError';
  }
}

export class ForbiddenError extends AppError {
  constructor(message = 'Access denied') {
    super(message, {
      code: 'FORBIDDEN',
      statusCode: 403,
    });
    this.name = 'ForbiddenError';
  }
}

export class NotFoundError extends AppError {
  constructor(message = 'Resource not found') {
    super(message, {
      code: 'NOT_FOUND',
      statusCode: 404,
    });
    this.name = 'NotFoundError';
  }
}

export class RateLimitError extends AppError {
  public readonly retryAfterSeconds: number;

  constructor(retryAfterSeconds: number) {
    super('Too many requests', {
      code: 'RATE_LIMITED',
      statusCode: 429,
    });
    this.name = 'RateLimitError';
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * Format an error into a structured API response.
 * Never includes stack traces or internal details.
 */
export function formatErrorResponse(error: unknown): {
  body: { error: { code: string; message: string; details?: unknown[] } };
  status: number;
} {
  if (error instanceof AppError) {
    return {
      body: {
        error: {
          code: error.code,
          message: error.message,
          ...(error.details.length > 0 ? { details: error.details } : {}),
        },
      },
      status: error.statusCode,
    };
  }

  // Unknown errors — never leak internals
  return {
    body: {
      error: {
        code: 'INTERNAL_ERROR',
        message: 'An unexpected error occurred',
      },
    },
    status: 500,
  };
}
