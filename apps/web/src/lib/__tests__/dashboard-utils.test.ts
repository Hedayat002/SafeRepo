import { describe, it, expect } from 'vitest';
import {
  getSeverityColor,
  getSeverityLabel,
  getStatusDisplay,
  isTerminalStatus,
  formatDuration,
  formatRelativeTime,
  buildFindingsFilterParams,
  computeSeverityCounts,
  computeSeverityPercentages,
  getSeverityBadgeClasses,
  getStatusBadgeClasses,
  SEVERITY_LEVELS,
  SCAN_STATUSES,
  TERMINAL_STATUSES,
} from '../dashboard-utils';

describe('dashboard-utils', () => {
  describe('SEVERITY_LEVELS and SCAN_STATUSES constants', () => {
    it('contains all 5 severities in priority order', () => {
      expect(SEVERITY_LEVELS).toEqual(['critical', 'high', 'medium', 'low', 'info']);
    });

    it('contains all 7 scan statuses', () => {
      expect(SCAN_STATUSES).toEqual([
        'queued',
        'cloning',
        'scanning',
        'normalizing',
        'completed',
        'failed',
        'timed_out',
      ]);
    });

    it('defines exactly 3 terminal statuses', () => {
      expect(TERMINAL_STATUSES).toEqual(['completed', 'failed', 'timed_out']);
    });
  });

  describe('getSeverityColor', () => {
    it('returns correct light mode colors', () => {
      expect(getSeverityColor('critical', 'light')).toBe('#DC2626');
      expect(getSeverityColor('high', 'light')).toBe('#EA580C');
      expect(getSeverityColor('medium', 'light')).toBe('#CA8A04');
      expect(getSeverityColor('low', 'light')).toBe('#2563EB');
      expect(getSeverityColor('info', 'light')).toBe('#6B7280');
    });

    it('returns correct dark mode colors', () => {
      expect(getSeverityColor('critical', 'dark')).toBe('#EF4444');
      expect(getSeverityColor('high', 'dark')).toBe('#F97316');
      expect(getSeverityColor('medium', 'dark')).toBe('#EAB308');
      expect(getSeverityColor('low', 'dark')).toBe('#3B82F6');
      expect(getSeverityColor('info', 'dark')).toBe('#9CA3AF');
    });

    it('returns fallback color for unknown or null inputs', () => {
      expect(getSeverityColor('unknown', 'light')).toBe('#6B7280');
      expect(getSeverityColor(null, 'light')).toBe('#6B7280');
      expect(getSeverityColor(undefined, 'dark')).toBe('#9CA3AF');
    });
  });

  describe('getSeverityLabel', () => {
    it('returns capitalized labels for valid severities', () => {
      expect(getSeverityLabel('critical')).toBe('Critical');
      expect(getSeverityLabel('high')).toBe('High');
      expect(getSeverityLabel('medium')).toBe('Medium');
      expect(getSeverityLabel('low')).toBe('Low');
      expect(getSeverityLabel('info')).toBe('Info');
    });

    it('returns Unknown for invalid or missing severities', () => {
      expect(getSeverityLabel('invalid')).toBe('Unknown');
      expect(getSeverityLabel(null)).toBe('Unknown');
      expect(getSeverityLabel(undefined)).toBe('Unknown');
    });
  });

  describe('getStatusDisplay', () => {
    it('returns metadata for all 7 statuses', () => {
      expect(getStatusDisplay('queued')).toEqual({ label: 'Queued', color: 'gray', icon: '○' });
      expect(getStatusDisplay('cloning')).toEqual({ label: 'Cloning', color: 'blue', icon: '◌' });
      expect(getStatusDisplay('scanning')).toEqual({ label: 'Scanning', color: 'blue', icon: '◉' });
      expect(getStatusDisplay('normalizing')).toEqual({ label: 'Normalizing', color: 'blue', icon: '◎' });
      expect(getStatusDisplay('completed')).toEqual({ label: 'Completed', color: 'green', icon: '●' });
      expect(getStatusDisplay('failed')).toEqual({ label: 'Failed', color: 'red', icon: '✕' });
      expect(getStatusDisplay('timed_out')).toEqual({ label: 'Timed Out', color: 'orange', icon: '⏱' });
    });

    it('returns fallback for unknown or empty statuses', () => {
      expect(getStatusDisplay('unknown')).toEqual({ label: 'Unknown', color: 'gray', icon: '?' });
      expect(getStatusDisplay(null)).toEqual({ label: 'Unknown', color: 'gray', icon: '?' });
    });
  });

  describe('isTerminalStatus', () => {
    it('returns true for terminal statuses', () => {
      expect(isTerminalStatus('completed')).toBe(true);
      expect(isTerminalStatus('failed')).toBe(true);
      expect(isTerminalStatus('timed_out')).toBe(true);
      expect(isTerminalStatus('COMPLETED')).toBe(true);
    });

    it('returns false for non-terminal statuses', () => {
      expect(isTerminalStatus('queued')).toBe(false);
      expect(isTerminalStatus('cloning')).toBe(false);
      expect(isTerminalStatus('scanning')).toBe(false);
      expect(isTerminalStatus('normalizing')).toBe(false);
    });

    it('returns false for null, undefined, and unrecognized values', () => {
      expect(isTerminalStatus(null)).toBe(false);
      expect(isTerminalStatus(undefined)).toBe(false);
      expect(isTerminalStatus('')).toBe(false);
      expect(isTerminalStatus('pending')).toBe(false);
    });
  });

  describe('formatDuration', () => {
    it('formats 0 and sub-second durations', () => {
      expect(formatDuration(0)).toBe('0s');
      expect(formatDuration(500)).toBe('< 1s');
    });

    it('formats seconds', () => {
      expect(formatDuration(45000)).toBe('45s');
    });

    it('formats minutes and seconds', () => {
      expect(formatDuration(135000)).toBe('2m 15s');
    });

    it('formats hours, minutes, and seconds', () => {
      expect(formatDuration(3665000)).toBe('1h 1m 5s');
    });

    it('handles negative, null, and invalid inputs', () => {
      expect(formatDuration(null)).toBe('—');
      expect(formatDuration(undefined)).toBe('—');
      expect(formatDuration(-100)).toBe('—');
      expect(formatDuration(NaN)).toBe('—');
    });
  });

  describe('formatRelativeTime', () => {
    const baseNow = new Date('2026-09-08T12:00:00.000Z');

    it('formats recent events', () => {
      const dateJustNow = new Date('2026-09-08T11:59:45.000Z');
      expect(formatRelativeTime(dateJustNow, baseNow)).toBe('just now');

      const date45s = new Date('2026-09-08T11:59:15.000Z');
      expect(formatRelativeTime(date45s, baseNow)).toBe('45 seconds ago');
    });

    it('formats minutes', () => {
      const date1m = new Date('2026-09-08T11:59:00.000Z');
      expect(formatRelativeTime(date1m, baseNow)).toBe('1 minute ago');

      const date5m = new Date('2026-09-08T11:55:00.000Z');
      expect(formatRelativeTime(date5m, baseNow)).toBe('5 minutes ago');
    });

    it('formats hours', () => {
      const date1h = new Date('2026-09-08T11:00:00.000Z');
      expect(formatRelativeTime(date1h, baseNow)).toBe('1 hour ago');

      const date4h = new Date('2026-09-08T08:00:00.000Z');
      expect(formatRelativeTime(date4h, baseNow)).toBe('4 hours ago');
    });

    it('formats days', () => {
      const date1d = new Date('2026-09-07T12:00:00.000Z');
      expect(formatRelativeTime(date1d, baseNow)).toBe('1 day ago');

      const date5d = new Date('2026-09-03T12:00:00.000Z');
      expect(formatRelativeTime(date5d, baseNow)).toBe('5 days ago');
    });

    it('formats months and years', () => {
      const date1mo = new Date('2026-08-01T12:00:00.000Z');
      expect(formatRelativeTime(date1mo, baseNow)).toBe('1 month ago');

      const date1yr = new Date('2025-08-01T12:00:00.000Z');
      expect(formatRelativeTime(date1yr, baseNow)).toBe('1 year ago');
    });

    it('handles future and invalid dates', () => {
      const futureDate = new Date('2026-09-08T13:00:00.000Z');
      expect(formatRelativeTime(futureDate, baseNow)).toBe('in the future');
      expect(formatRelativeTime('invalid-date', baseNow)).toBe('—');
      expect(formatRelativeTime(null, baseNow)).toBe('—');
    });
  });

  describe('buildFindingsFilterParams', () => {
    it('returns empty string when no filters set or all are "all"', () => {
      expect(buildFindingsFilterParams({})).toBe('');
      expect(buildFindingsFilterParams({ severity: 'all', category: 'all', scanner: 'all' })).toBe('');
    });

    it('builds query string for single filter', () => {
      expect(buildFindingsFilterParams({ severity: 'critical' })).toBe('?severity=critical');
      expect(buildFindingsFilterParams({ category: 'sast' })).toBe('?category=sast');
    });

    it('builds query string for multiple combined filters', () => {
      const query = buildFindingsFilterParams({
        severity: 'high',
        category: 'dependency',
        scanner: 'trivy',
      });
      expect(query).toBe('?severity=high&category=dependency&scanner=trivy');
    });
  });

  describe('computeSeverityCounts', () => {
    it('extracts all severities in priority order with counts', () => {
      const summary = {
        total: 8,
        critical: 2,
        high: 3,
        medium: 2,
        low: 1,
        info: 0,
      };

      const counts = computeSeverityCounts(summary);
      expect(counts).toHaveLength(5);
      expect(counts[0]).toEqual({
        severity: 'critical',
        label: 'Critical',
        count: 2,
        color: '#DC2626',
      });
      expect(counts[1].count).toBe(3);
      expect(counts[2].count).toBe(2);
      expect(counts[3].count).toBe(1);
      expect(counts[4].count).toBe(0);
    });

    it('handles null, undefined, or missing fields safely', () => {
      const countsNull = computeSeverityCounts(null);
      expect(countsNull).toHaveLength(5);
      expect(countsNull.every((c) => c.count === 0)).toBe(true);

      const partialSummary = { critical: 5 };
      const countsPartial = computeSeverityCounts(partialSummary);
      expect(countsPartial[0].count).toBe(5);
      expect(countsPartial[1].count).toBe(0);
    });
  });

  describe('computeSeverityPercentages', () => {
    it('calculates correct percentages when total > 0', () => {
      const summary = {
        total: 10,
        critical: 5,
        high: 3,
        medium: 2,
        low: 0,
        info: 0,
      };

      const items = computeSeverityPercentages(summary);
      expect(items[0].percentage).toBe(50);
      expect(items[1].percentage).toBe(30);
      expect(items[2].percentage).toBe(20);
      expect(items[3].percentage).toBe(0);
      expect(items[4].percentage).toBe(0);
    });

    it('protects against division by zero when total is 0', () => {
      const summary = {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };

      const items = computeSeverityPercentages(summary);
      expect(items.every((item) => item.percentage === 0)).toBe(true);
    });
  });

  describe('Badge CSS helper functions', () => {
    it('returns appropriate badge classes for each severity', () => {
      expect(getSeverityBadgeClasses('critical')).toContain('bg-red-100');
      expect(getSeverityBadgeClasses('high')).toContain('bg-orange-100');
      expect(getSeverityBadgeClasses('medium')).toContain('bg-yellow-100');
      expect(getSeverityBadgeClasses('low')).toContain('bg-blue-100');
      expect(getSeverityBadgeClasses('info')).toContain('bg-gray-100');
      expect(getSeverityBadgeClasses('unknown')).toContain('bg-gray-100');
    });

    it('returns appropriate status pill classes for each status', () => {
      expect(getStatusBadgeClasses('completed')).toContain('bg-green-100');
      expect(getStatusBadgeClasses('failed')).toContain('bg-red-100');
      expect(getStatusBadgeClasses('timed_out')).toContain('bg-orange-100');
      expect(getStatusBadgeClasses('scanning')).toContain('bg-blue-100');
      expect(getStatusBadgeClasses('queued')).toContain('bg-gray-100');
    });
  });
});
