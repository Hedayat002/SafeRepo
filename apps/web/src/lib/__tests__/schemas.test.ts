import { describe, it, expect } from 'vitest';
import {
  reposQuerySchema,
  repoParamsSchema,
  oauthCallbackSchema,
} from '@/lib/schemas';

describe('Zod Validation Schemas', () => {
  describe('reposQuerySchema', () => {
    it('should apply defaults when no query params are provided', () => {
      const result = reposQuerySchema.safeParse({});
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.page).toBe(1);
        expect(result.data.per_page).toBe(30);
      }
    });

    it('should parse valid query strings into numbers', () => {
      const result = reposQuerySchema.safeParse({ page: '2', per_page: '50' });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.page).toBe(2);
        expect(result.data.per_page).toBe(50);
      }
    });

    it('should reject invalid page numbers', () => {
      const result = reposQuerySchema.safeParse({ page: '0' });
      expect(result.success).toBe(false);

      const negResult = reposQuerySchema.safeParse({ page: '-1' });
      expect(negResult.success).toBe(false);
    });

    it('should reject per_page greater than 100 or less than 1', () => {
      const tooHigh = reposQuerySchema.safeParse({ per_page: '101' });
      expect(tooHigh.success).toBe(false);

      const tooLow = reposQuerySchema.safeParse({ per_page: '0' });
      expect(tooLow.success).toBe(false);
    });
  });

  describe('repoParamsSchema', () => {
    it('should accept valid owner and name', () => {
      const result = repoParamsSchema.safeParse({
        owner: 'facebook',
        name: 'react',
      });
      expect(result.success).toBe(true);
    });

    it('should reject empty owner or name', () => {
      const emptyOwner = repoParamsSchema.safeParse({
        owner: '',
        name: 'react',
      });
      expect(emptyOwner.success).toBe(false);

      const emptyName = repoParamsSchema.safeParse({
        owner: 'facebook',
        name: '',
      });
      expect(emptyName.success).toBe(false);
    });
  });

  describe('oauthCallbackSchema', () => {
    it('should accept valid code and state', () => {
      const result = oauthCallbackSchema.safeParse({
        code: 'auth_code_123',
        state: 'csrf_state_456',
      });
      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data.code).toBe('auth_code_123');
        expect(result.data.state).toBe('csrf_state_456');
      }
    });

    it('should reject missing code or state', () => {
      const missingCode = oauthCallbackSchema.safeParse({
        state: 'csrf_state_456',
      });
      expect(missingCode.success).toBe(false);

      const missingState = oauthCallbackSchema.safeParse({
        code: 'auth_code_123',
      });
      expect(missingState.success).toBe(false);
    });
  });
});
