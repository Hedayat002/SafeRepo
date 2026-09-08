import type { FindingSeverity, ScanStatus, ScanSummary } from '@/types';

/**
 * Severity levels in descending order of priority.
 */
export const SEVERITY_LEVELS: readonly FindingSeverity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'info',
] as const;

/**
 * All valid scan lifecycle statuses.
 */
export const SCAN_STATUSES: readonly ScanStatus[] = [
  'queued',
  'cloning',
  'scanning',
  'normalizing',
  'completed',
  'failed',
  'timed_out',
] as const;

/**
 * Terminal scan statuses where processing has halted.
 */
export const TERMINAL_STATUSES: readonly ScanStatus[] = [
  'completed',
  'failed',
  'timed_out',
] as const;

/**
 * Maps severity to hex color tokens according to Phase 07 specification.
 */
export function getSeverityColor(
  severity: string | null | undefined,
  mode: 'light' | 'dark' = 'light'
): string {
  const isDark = mode === 'dark';

  switch (severity?.toLowerCase()) {
    case 'critical':
      return isDark ? '#EF4444' : '#DC2626';
    case 'high':
      return isDark ? '#F97316' : '#EA580C';
    case 'medium':
      return isDark ? '#EAB308' : '#CA8A04';
    case 'low':
      return isDark ? '#3B82F6' : '#2563EB';
    case 'info':
      return isDark ? '#9CA3AF' : '#6B7280';
    default:
      return isDark ? '#9CA3AF' : '#6B7280';
  }
}

/**
 * Maps severity to human-readable label.
 */
export function getSeverityLabel(severity: string | null | undefined): string {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'Critical';
    case 'high':
      return 'High';
    case 'medium':
      return 'Medium';
    case 'low':
      return 'Low';
    case 'info':
      return 'Info';
    default:
      return 'Unknown';
  }
}

/**
 * Metadata representation for scan statuses.
 */
export interface StatusDisplay {
  label: string;
  color: 'gray' | 'blue' | 'green' | 'red' | 'orange';
  icon: string;
}

/**
 * Returns formatted status metadata for badge rendering.
 */
export function getStatusDisplay(status: string | null | undefined): StatusDisplay {
  switch (status?.toLowerCase()) {
    case 'queued':
      return { label: 'Queued', color: 'gray', icon: '○' };
    case 'cloning':
      return { label: 'Cloning', color: 'blue', icon: '◌' };
    case 'scanning':
      return { label: 'Scanning', color: 'blue', icon: '◉' };
    case 'normalizing':
      return { label: 'Normalizing', color: 'blue', icon: '◎' };
    case 'completed':
      return { label: 'Completed', color: 'green', icon: '●' };
    case 'failed':
      return { label: 'Failed', color: 'red', icon: '✕' };
    case 'timed_out':
      return { label: 'Timed Out', color: 'orange', icon: '⏱' };
    default:
      return { label: 'Unknown', color: 'gray', icon: '?' };
  }
}

/**
 * Determines whether a scan status is terminal (polling can halt).
 */
export function isTerminalStatus(status: string | null | undefined): boolean {
  if (!status) return false;
  return TERMINAL_STATUSES.includes(status.toLowerCase() as ScanStatus);
}

/**
 * Formats duration in milliseconds into a concise, human-readable string.
 */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || isNaN(ms) || ms < 0) {
    return '—';
  }

  if (ms === 0) {
    return '0s';
  }

  if (ms < 1000) {
    return '< 1s';
  }

  const totalSeconds = Math.floor(ms / 1000);
  const hours = Math.floor(totalSeconds / 3600);
  const minutes = Math.floor((totalSeconds % 3600) / 60);
  const seconds = totalSeconds % 60;

  const parts: string[] = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (seconds > 0 || parts.length === 0) parts.push(`${seconds}s`);

  return parts.join(' ');
}

/**
 * Formats a Date or timestamp into a friendly relative time description.
 */
export function formatRelativeTime(
  date: Date | string | null | undefined,
  referenceNow?: Date
): string {
  if (!date) return '—';

  const targetDate = typeof date === 'string' ? new Date(date) : date;
  if (isNaN(targetDate.getTime())) return '—';

  const now = referenceNow ?? new Date();
  const diffMs = now.getTime() - targetDate.getTime();

  if (diffMs < 0) return 'in the future';

  const diffSeconds = Math.floor(diffMs / 1000);
  if (diffSeconds < 30) return 'just now';
  if (diffSeconds < 60) return `${diffSeconds} seconds ago`;

  const diffMinutes = Math.floor(diffSeconds / 60);
  if (diffMinutes === 1) return '1 minute ago';
  if (diffMinutes < 60) return `${diffMinutes} minutes ago`;

  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours === 1) return '1 hour ago';
  if (diffHours < 24) return `${diffHours} hours ago`;

  const diffDays = Math.floor(diffHours / 24);
  if (diffDays === 1) return '1 day ago';
  if (diffDays < 30) return `${diffDays} days ago`;

  const diffMonths = Math.floor(diffDays / 30);
  if (diffMonths === 1) return '1 month ago';
  if (diffMonths < 12) return `${diffMonths} months ago`;

  const diffYears = Math.floor(diffDays / 365);
  if (diffYears === 1) return '1 year ago';
  return `${diffYears} years ago`;
}

/**
 * Builds URL search parameters string for findings filtering.
 */
export function buildFindingsFilterParams(filters: {
  severity?: string;
  category?: string;
  scanner?: string;
}): string {
  const params = new URLSearchParams();
  if (filters.severity && filters.severity !== 'all') {
    params.set('severity', filters.severity);
  }
  if (filters.category && filters.category !== 'all') {
    params.set('category', filters.category);
  }
  if (filters.scanner && filters.scanner !== 'all') {
    params.set('scanner', filters.scanner);
  }
  const queryString = params.toString();
  return queryString ? `?${queryString}` : '';
}

/**
 * Severity count entry for UI presentation.
 */
export interface SeverityCountItem {
  severity: FindingSeverity;
  label: string;
  count: number;
  color: string;
}

/**
 * Extracts ordered severity counts from scan summary, handling null/undefined safely.
 */
export function computeSeverityCounts(
  summary?: Partial<ScanSummary> | null,
  mode: 'light' | 'dark' = 'light'
): SeverityCountItem[] {
  return SEVERITY_LEVELS.map((severity) => ({
    severity,
    label: getSeverityLabel(severity),
    count: Math.max(0, summary?.[severity] ?? 0),
    color: getSeverityColor(severity, mode),
  }));
}

/**
 * Severity distribution percentage entry for visualization.
 */
export interface SeverityPercentageItem extends SeverityCountItem {
  percentage: number;
}

/**
 * Computes proportional percentages per severity for chart rendering.
 * Protected against division by zero.
 */
export function computeSeverityPercentages(
  summary?: Partial<ScanSummary> | null,
  mode: 'light' | 'dark' = 'light'
): SeverityPercentageItem[] {
  const counts = computeSeverityCounts(summary, mode);
  const total = counts.reduce((sum, item) => sum + item.count, 0);

  return counts.map((item) => ({
    ...item,
    percentage: total > 0 ? Math.round((item.count / total) * 100) : 0,
  }));
}

/**
 * Returns Tailwind CSS utility classes for styling severity badges.
 */
export function getSeverityBadgeClasses(severity: string | null | undefined): string {
  switch (severity?.toLowerCase()) {
    case 'critical':
      return 'bg-red-100 text-red-800 border-red-200 dark:bg-red-950/50 dark:text-red-300 dark:border-red-900';
    case 'high':
      return 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-950/50 dark:text-orange-300 dark:border-orange-900';
    case 'medium':
      return 'bg-yellow-100 text-yellow-800 border-yellow-200 dark:bg-yellow-950/50 dark:text-yellow-300 dark:border-yellow-900';
    case 'low':
      return 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-950/50 dark:text-blue-300 dark:border-blue-900';
    case 'info':
      return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700';
    default:
      return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700';
  }
}

/**
 * Returns Tailwind CSS utility classes for styling status pills.
 */
export function getStatusBadgeClasses(status: string | null | undefined): string {
  const display = getStatusDisplay(status);
  switch (display.color) {
    case 'green':
      return 'bg-green-100 text-green-800 border-green-200 dark:bg-green-950/50 dark:text-green-300 dark:border-green-900';
    case 'red':
      return 'bg-red-100 text-red-800 border-red-200 dark:bg-red-950/50 dark:text-red-300 dark:border-red-900';
    case 'orange':
      return 'bg-orange-100 text-orange-800 border-orange-200 dark:bg-orange-950/50 dark:text-orange-300 dark:border-orange-900';
    case 'blue':
      return 'bg-blue-100 text-blue-800 border-blue-200 dark:bg-blue-950/50 dark:text-blue-300 dark:border-blue-900';
    case 'gray':
    default:
      return 'bg-gray-100 text-gray-800 border-gray-200 dark:bg-gray-800 dark:text-gray-300 dark:border-gray-700';
  }
}
