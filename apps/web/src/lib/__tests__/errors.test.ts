import { describe, it, expect } from 'vitest';
import {
  AppError,
  ValidationError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  RateLimitError,
  formatErrorResponse,
} from '@/lib/errors';

describe('Error Classes', () => {
  describe('AppError', () => {
    it('should create with defaults', () => {
      const error = new AppError('Something failed');
      expect(error.message).toBe('Something failed');
      expect(error.code).toBe('INTERNAL_ERROR');
      expect(error.statusCode).toBe(500);
      expect(error.details).toEqual([]);
      expect(error.name).toBe('AppError');
    });

    it('should create with custom options', () => {
      const error = new AppError('Custom error', {
        code: 'CUSTOM_CODE',
        statusCode: 418,
        details: [{ field: 'name' }],
      });
      expect(error.code).toBe('CUSTOM_CODE');
      expect(error.statusCode).toBe(418);
      expect(error.details).toEqual([{ field: 'name' }]);
    });
  });

  describe('ValidationError', () => {
    it('should have correct defaults', () => {
      const error = new ValidationError('Invalid input');
      expect(error.code).toBe('VALIDATION_ERROR');
      expect(error.statusCode).toBe(400);
      expect(error.name).toBe('ValidationError');
    });

    it('should accept details', () => {
      const details = [{ path: ['name'], message: 'Required' }];
      const error = new ValidationError('Invalid input', details);
      expect(error.details).toEqual(details);
    });
  });

  describe('UnauthorizedError', () => {
    it('should have correct defaults', () => {
      const error = new UnauthorizedError();
      expect(error.code).toBe('UNAUTHORIZED');
      expect(error.statusCode).toBe(401);
      expect(error.message).toBe('Authentication required');
    });

    it('should accept custom message', () => {
      const error = new UnauthorizedError('Token expired');
      expect(error.message).toBe('Token expired');
    });
  });

  describe('ForbiddenError', () => {
    it('should have correct defaults', () => {
      const error = new ForbiddenError();
      expect(error.code).toBe('FORBIDDEN');
      expect(error.statusCode).toBe(403);
    });
  });

  describe('NotFoundError', () => {
    it('should have correct defaults', () => {
      const error = new NotFoundError();
      expect(error.code).toBe('NOT_FOUND');
      expect(error.statusCode).toBe(404);
    });
  });

  describe('RateLimitError', () => {
    it('should have correct defaults', () => {
      const error = new RateLimitError(60);
      expect(error.code).toBe('RATE_LIMITED');
      expect(error.statusCode).toBe(429);
      expect(error.retryAfterSeconds).toBe(60);
    });
  });
});

describe('formatErrorResponse', () => {
  it('should format AppError correctly', () => {
    const error = new ValidationError('Bad input', [{ field: 'name' }]);
    const { body, status } = formatErrorResponse(error);

    expect(status).toBe(400);
    expect(body.error.code).toBe('VALIDATION_ERROR');
    expect(body.error.message).toBe('Bad input');
    expect(body.error.details).toEqual([{ field: 'name' }]);
  });

  it('should not include details when empty', () => {
    const error = new UnauthorizedError();
    const { body } = formatErrorResponse(error);

    expect(body.error.details).toBeUndefined();
  });

  it('should handle unknown errors safely', () => {
    const { body, status } = formatErrorResponse(new Error('unexpected'));

    expect(status).toBe(500);
    expect(body.error.code).toBe('INTERNAL_ERROR');
    expect(body.error.message).toBe('An unexpected error occurred');
  });

  it('should handle non-Error objects', () => {
    const { body, status } = formatErrorResponse('string error');

    expect(status).toBe(500);
    expect(body.error.code).toBe('INTERNAL_ERROR');
  });

  it('should never leak stack traces', () => {
    const error = new AppError('test');
    const { body } = formatErrorResponse(error);

    expect(JSON.stringify(body)).not.toContain('stack');
    expect(JSON.stringify(body)).not.toContain('at ');
  });
});
