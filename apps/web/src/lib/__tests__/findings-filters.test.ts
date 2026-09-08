import { describe, it, expect } from 'vitest';
import {
  buildFilterQuery,
  parseFilterParams,
  getPageRange,
  clampPage,
  isValidPage,
  type FindingsFilterState,
} from '../findings-filters';

describe('findings-filters module', () => {
  describe('buildFilterQuery', () => {
    it('returns empty object when no filters or "all" filters are provided', () => {
      expect(buildFilterQuery({})).toEqual({});
      expect(
        buildFilterQuery({
          severity: 'all',
          category: 'all',
          scanner: 'all',
          page: 1,
        })
      ).toEqual({});
    });

    it('builds query parameters for single filter', () => {
      expect(buildFilterQuery({ severity: 'critical' })).toEqual({
        severity: 'critical',
      });
      expect(buildFilterQuery({ category: 'sast' })).toEqual({
        category: 'sast',
      });
      expect(buildFilterQuery({ scanner: 'gitleaks' })).toEqual({
        scanner: 'gitleaks',
      });
    });

    it('builds query parameters for combined multiple filters', () => {
      const filters: FindingsFilterState = {
        severity: 'high',
        category: 'dependency',
        scanner: 'trivy',
        page: 3,
      };
      expect(buildFilterQuery(filters)).toEqual({
        severity: 'high',
        category: 'dependency',
        scanner: 'trivy',
        page: '3',
      });
    });

    it('omits page when page is 1 or undefined', () => {
      expect(buildFilterQuery({ severity: 'low', page: 1 })).toEqual({
        severity: 'low',
      });
      expect(buildFilterQuery({ severity: 'low' })).toEqual({
        severity: 'low',
      });
    });
  });

  describe('parseFilterParams', () => {
    it('parses valid filter query parameters from URLSearchParams', () => {
      const searchParams = new URLSearchParams(
        'severity=critical&category=sast&scanner=semgrep&page=2'
      );
      const parsed = parseFilterParams(searchParams);
      expect(parsed).toEqual({
        severity: 'critical',
        category: 'sast',
        scanner: 'semgrep',
        page: 2,
      });
    });

    it('parses valid filter query parameters from plain record', () => {
      const parsed = parseFilterParams({
        severity: 'high',
        category: 'secret',
        scanner: 'gitleaks',
        page: '5',
      });
      expect(parsed).toEqual({
        severity: 'high',
        category: 'secret',
        scanner: 'gitleaks',
        page: 5,
      });
    });

    it('falls back to "all" for invalid or unknown filter values', () => {
      const parsed = parseFilterParams({
        severity: 'extreme',
        category: 'unknown_cat',
        scanner: 'random_scanner',
        page: 'invalid_page',
      });
      expect(parsed).toEqual({
        severity: 'all',
        category: 'all',
        scanner: 'all',
        page: 1,
      });
    });

    it('handles negative or zero page values by defaulting to page 1', () => {
      expect(parseFilterParams({ page: '0' }).page).toBe(1);
      expect(parseFilterParams({ page: '-5' }).page).toBe(1);
    });

    it('handles array values in searchParams record', () => {
      const parsed = parseFilterParams({
        severity: ['medium', 'low'],
        page: ['3'],
      });
      expect(parsed.severity).toBe('medium');
      expect(parsed.page).toBe(3);
    });
  });

  describe('getPageRange', () => {
    it('returns empty array when totalPages <= 0', () => {
      expect(getPageRange(1, 0)).toEqual([]);
      expect(getPageRange(1, -5)).toEqual([]);
    });

    it('returns [1] when totalPages === 1', () => {
      expect(getPageRange(1, 1)).toEqual([1]);
    });

    it('returns direct sequential range when totalPages is small', () => {
      expect(getPageRange(1, 5)).toEqual([1, 2, 3, 4, 5]);
      expect(getPageRange(3, 7)).toEqual([1, 2, 3, 4, 5, 6, 7]);
    });

    it('formats pagination at start of large collection', () => {
      const range = getPageRange(1, 20);
      expect(range).toEqual([1, 2, 3, 4, 5, '...', 20]);
    });

    it('formats pagination in middle of large collection', () => {
      const range = getPageRange(10, 20);
      expect(range).toEqual([1, '...', 9, 10, 11, '...', 20]);
    });

    it('formats pagination at end of large collection', () => {
      const range = getPageRange(20, 20);
      expect(range).toEqual([1, '...', 16, 17, 18, 19, 20]);
    });
  });

  describe('clampPage', () => {
    it('clamps pages below 1 to 1', () => {
      expect(clampPage(0, 10)).toBe(1);
      expect(clampPage(-5, 10)).toBe(1);
      expect(clampPage(null, 10)).toBe(1);
      expect(clampPage(undefined, 10)).toBe(1);
      expect(clampPage('abc', 10)).toBe(1);
    });

    it('clamps pages above totalPages to totalPages', () => {
      expect(clampPage(15, 10)).toBe(10);
      expect(clampPage('99', 5)).toBe(5);
    });

    it('returns original page number when within bounds', () => {
      expect(clampPage(4, 10)).toBe(4);
      expect(clampPage('7', 10)).toBe(7);
    });
  });

  describe('isValidPage', () => {
    it('returns true for integers within [1, totalPages]', () => {
      expect(isValidPage(1, 5)).toBe(true);
      expect(isValidPage(3, 5)).toBe(true);
      expect(isValidPage(5, 5)).toBe(true);
      expect(isValidPage('4', 5)).toBe(true);
    });

    it('returns false for numbers outside valid bounds', () => {
      expect(isValidPage(0, 5)).toBe(false);
      expect(isValidPage(-1, 5)).toBe(false);
      expect(isValidPage(6, 5)).toBe(false);
      expect(isValidPage(null, 5)).toBe(false);
      expect(isValidPage(undefined, 5)).toBe(false);
      expect(isValidPage(1.5, 5)).toBe(false);
      expect(isValidPage('abc', 5)).toBe(false);
    });
  });
});
