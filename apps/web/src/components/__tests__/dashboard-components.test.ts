import { describe, it, expect } from 'vitest';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';

// UI Primitives
import { Spinner } from '@/components/ui/Spinner';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Card, CardHeader, CardTitle, CardDescription } from '@/components/ui/Card';
import { Select } from '@/components/ui/Select';

// Dashboard Components
import { ScanStatusBadge } from '@/components/dashboard/ScanStatusBadge';
import { SeveritySummary } from '@/components/dashboard/SeveritySummary';
import { SeverityChart } from '@/components/dashboard/SeverityChart';
import { EmptyState } from '@/components/dashboard/EmptyState';
import { Pagination } from '@/components/dashboard/Pagination';
import { RemediationPanel } from '@/components/dashboard/RemediationPanel';
import { FindingRow } from '@/components/dashboard/FindingRow';
import { FindingsFilter } from '@/components/dashboard/FindingsFilter';
import { ScanCard } from '@/components/dashboard/ScanCard';
import type { FindingResponseData, ScanResponseData } from '@/types';

describe('dashboard-components rendering tests (react-dom/server)', () => {
  describe('ScanStatusBadge', () => {
    it('renders correct labels and icons for all 7 lifecycle statuses', () => {
      const statuses = [
        { status: 'queued', label: 'Queued', icon: '○' },
        { status: 'cloning', label: 'Cloning', icon: '◌' },
        { status: 'scanning', label: 'Scanning', icon: '◉' },
        { status: 'normalizing', label: 'Normalizing', icon: '◎' },
        { status: 'completed', label: 'Completed', icon: '●' },
        { status: 'failed', label: 'Failed', icon: '✕' },
        { status: 'timed_out', label: 'Timed Out', icon: '⏱' },
      ];

      for (const { status, label, icon } of statuses) {
        const html = renderToStaticMarkup(
          React.createElement(ScanStatusBadge, { status })
        );
        expect(html).toContain(label);
        if (status !== 'scanning' && status !== 'normalizing') {
          expect(html).toContain(icon);
        }
      }
    });

    it('renders animated ping elements for active scanning and normalizing states', () => {
      const scanningHtml = renderToStaticMarkup(
        React.createElement(ScanStatusBadge, { status: 'scanning' })
      );
      expect(scanningHtml).toContain('animate-ping');

      const normalizingHtml = renderToStaticMarkup(
        React.createElement(ScanStatusBadge, { status: 'normalizing' })
      );
      expect(normalizingHtml).toContain('animate-ping');
    });

    it('applies color-specific badge classes', () => {
      const completedHtml = renderToStaticMarkup(
        React.createElement(ScanStatusBadge, { status: 'completed' })
      );
      expect(completedHtml).toContain('bg-green-100');

      const failedHtml = renderToStaticMarkup(
        React.createElement(ScanStatusBadge, { status: 'failed' })
      );
      expect(failedHtml).toContain('bg-red-100');

      const timedOutHtml = renderToStaticMarkup(
        React.createElement(ScanStatusBadge, { status: 'timed_out' })
      );
      expect(timedOutHtml).toContain('bg-orange-100');
    });
  });

  describe('SeveritySummary', () => {
    it('renders all 5 severity count badges when counts are present', () => {
      const summary = {
        total: 10,
        critical: 2,
        high: 3,
        medium: 1,
        low: 4,
        info: 0,
      };

      const html = renderToStaticMarkup(
        React.createElement(SeveritySummary, { summary })
      );

      expect(html).toContain('Critical:');
      expect(html).toContain('2');
      expect(html).toContain('High:');
      expect(html).toContain('3');
      expect(html).toContain('Medium:');
      expect(html).toContain('1');
      expect(html).toContain('Low:');
      expect(html).toContain('4');
      expect(html).toContain('Info:');
      expect(html).toContain('0');
    });

    it('handles null or missing summary without crashing', () => {
      const html = renderToStaticMarkup(
        React.createElement(SeveritySummary, { summary: null })
      );
      expect(html).toContain('Critical:');
      expect(html).toContain('0');
    });

    it('filters zero counts when showZeroCounts is false', () => {
      const summary = {
        total: 2,
        critical: 2,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };

      const html = renderToStaticMarkup(
        React.createElement(SeveritySummary, { summary, showZeroCounts: false })
      );
      expect(html).toContain('Critical:');
      expect(html).toContain('2');
      expect(html).not.toContain('High:');
    });
  });

  describe('SeverityChart', () => {
    it('renders distribution bars and legend values', () => {
      const summary = {
        total: 10,
        critical: 5,
        high: 3,
        medium: 2,
        low: 0,
        info: 0,
      };

      const html = renderToStaticMarkup(
        React.createElement(SeverityChart, { summary })
      );
      expect(html).toContain('width:50%');
      expect(html).toContain('width:30%');
      expect(html).toContain('width:20%');
      expect(html).toContain('Critical:');
      expect(html).toContain('5');
    });

    it('renders neutral bar when total findings count is 0', () => {
      const summary = {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };

      const html = renderToStaticMarkup(
        React.createElement(SeverityChart, { summary })
      );
      expect(html).toContain('title="No findings detected"');
    });
  });

  describe('EmptyState', () => {
    it('renders no-scans empty state with action CTA', () => {
      const html = renderToStaticMarkup(
        React.createElement(EmptyState, { type: 'no-scans' })
      );
      expect(html).toContain('No scans yet');
      expect(html).toContain('Start New Scan');
      expect(html).toContain('/dashboard/new-scan');
    });

    it('renders no-findings clean state with positive message', () => {
      const html = renderToStaticMarkup(
        React.createElement(EmptyState, { type: 'no-findings' })
      );
      expect(html).toContain('No security findings detected');
      expect(html).toContain('repository appears clean');
    });

    it('renders no-filter-matches state with reset action', () => {
      const html = renderToStaticMarkup(
        React.createElement(EmptyState, {
          type: 'no-filter-matches',
          onReset: () => {},
        })
      );
      expect(html).toContain('No findings match the selected filters');
      expect(html).toContain('Clear filters');
    });

    it('renders no-repos state with permission notice', () => {
      const html = renderToStaticMarkup(
        React.createElement(EmptyState, { type: 'no-repos' })
      );
      expect(html).toContain('No repositories found');
      expect(html).toContain('Ensure your GitHub App has access');
    });
  });

  describe('Pagination', () => {
    it('returns null when totalPages <= 1', () => {
      const html = renderToStaticMarkup(
        React.createElement(Pagination, { currentPage: 1, totalPages: 1 })
      );
      expect(html).toBe('');
    });

    it('marks current page with aria-current="page"', () => {
      const html = renderToStaticMarkup(
        React.createElement(Pagination, { currentPage: 2, totalPages: 5 })
      );
      expect(html).toContain('aria-current="page"');
      expect(html).toContain('>2<');
    });

    it('disables Previous button on page 1', () => {
      const html = renderToStaticMarkup(
        React.createElement(Pagination, { currentPage: 1, totalPages: 5 })
      );
      expect(html).toContain('disabled=""');
      expect(html).toContain('aria-disabled="true"');
    });

    it('renders ellipsis for large page ranges', () => {
      const html = renderToStaticMarkup(
        React.createElement(Pagination, { currentPage: 1, totalPages: 20 })
      );
      expect(html).toContain('...');
      expect(html).toContain('>20<');
    });
  });

  describe('UI Primitives (Spinner, Badge, Button, Card, Select)', () => {
    it('renders Spinner with accessible attributes', () => {
      const html = renderToStaticMarkup(
        React.createElement(Spinner, { label: 'Checking...' })
      );
      expect(html).toContain('role="status"');
      expect(html).toContain('aria-label="Checking..."');
      expect(html).toContain('animate-spin');
    });

    it('renders Badge with variants and custom children', () => {
      const html = renderToStaticMarkup(
        // eslint-disable-next-line react/no-children-prop
        React.createElement(Badge, { variant: 'critical', children: 'CRITICAL' })
      );
      expect(html).toContain('CRITICAL');
      expect(html).toContain('bg-red-100');
    });

    it('renders Button in normal, disabled, and loading states', () => {
      const normalHtml = renderToStaticMarkup(
        // eslint-disable-next-line react/no-children-prop
        React.createElement(Button, { variant: 'primary', children: 'Submit' })
      );
      expect(normalHtml).toContain('Submit');
      expect(normalHtml).not.toContain('disabled=""');

      const loadingHtml = renderToStaticMarkup(
        // eslint-disable-next-line react/no-children-prop
        React.createElement(Button, { loading: true, children: 'Saving...' })
      );
      expect(loadingHtml).toContain('disabled=""');
      expect(loadingHtml).toContain('aria-busy="true"');
      expect(loadingHtml).toContain('animate-spin');
    });

    it('renders Card hierarchy', () => {
      const html = renderToStaticMarkup(
        React.createElement(
          Card,
          null,
          React.createElement(
            CardHeader,
            null,
            React.createElement(CardTitle, null, 'Card Headline'),
            React.createElement(CardDescription, null, 'Card details')
          ),
          React.createElement('div', null, 'Card Body')
        )
      );
      expect(html).toContain('Card Headline');
      expect(html).toContain('Card details');
      expect(html).toContain('Card Body');
    });

    it('renders Select with options, label, and error', () => {
      const html = renderToStaticMarkup(
        React.createElement(Select, {
          label: 'Filter Category',
          options: [
            { value: 'all', label: 'All' },
            { value: 'sast', label: 'SAST' },
          ],
          error: 'Required field',
          defaultValue: 'all',
        })
      );
      expect(html).toContain('Filter Category');
      expect(html).toContain('Required field');
      expect(html).toContain('value="sast"');
    });
  });

  describe('RemediationPanel', () => {
    it('renders remediation guidance, package details, and vulnerability ID', () => {
      const finding: FindingResponseData = {
        id: 'f-1',
        scanId: 's-1',
        scanner: 'trivy',
        category: 'dependency',
        severity: 'high',
        title: 'Vulnerability in express',
        description: 'Denial of service via body parser',
        file: 'package-lock.json',
        line: 12,
        package: 'express',
        packageVersion: '4.17.1',
        fixedVersion: '4.18.2',
        vulnerabilityId: 'CVE-2022-29078',
        remediation: 'Upgrade express to version 4.18.2 or newer.',
        fingerprint: 'fp-1',
        createdAt: '2026-09-08T12:00:00Z',
      };

      const html = renderToStaticMarkup(
        React.createElement(RemediationPanel, { finding })
      );
      expect(html).toContain('Remediation Guidance');
      expect(html).toContain('Upgrade express to version 4.18.2 or newer.');
      expect(html).toContain('express');
      expect(html).toContain('4.17.1');
      expect(html).toContain('4.18.2');
      expect(html).toContain('CVE-2022-29078');
    });
  });

  describe('FindingRow', () => {
    it('renders finding summary row with severity badge and file location', () => {
      const finding: FindingResponseData = {
        id: 'f-2',
        scanId: 's-1',
        scanner: 'semgrep',
        category: 'sast',
        severity: 'critical',
        title: 'SQL Injection in Query Builder',
        description: 'Raw query constructed with user input',
        file: 'src/api/user.ts',
        line: 88,
        vulnerabilityId: 'CWE-89',
        fingerprint: 'fp-2',
        createdAt: '2026-09-08T12:00:00Z',
      };

      const html = renderToStaticMarkup(
        React.createElement(FindingRow, { finding })
      );
      expect(html).toContain('CRITICAL');
      expect(html).toContain('SQL Injection in Query Builder');
      expect(html).toContain('src/api/user.ts:88');
      expect(html).toContain('sast');
      expect(html).toContain('semgrep');
    });
  });

  describe('FindingsFilter', () => {
    it('renders all three filter dropdowns and active filter tags', () => {
      const html = renderToStaticMarkup(
        React.createElement(FindingsFilter, {
          filters: {
            severity: 'critical',
            category: 'sast',
            scanner: 'all',
          },
          onFilterChange: () => {},
        })
      );
      expect(html).toContain('Filter by Severity');
      expect(html).toContain('Filter by Category');
      expect(html).toContain('Filter by Scanner');
      expect(html).toContain('Active filters:');
      expect(html).toContain('Severity: critical');
      expect(html).toContain('Category: sast');
    });
  });

  describe('ScanCard', () => {
    it('renders repository name, branch, commit, duration, and status', () => {
      const scan: ScanResponseData = {
        id: 'scan-123',
        userId: 'user-1',
        repositoryOwner: 'facebook',
        repositoryName: 'react',
        repositoryUrl: 'https://github.com/facebook/react',
        branch: 'main',
        commitSha: 'a1b2c3d4e5f6',
        status: 'completed',
        scanners: ['semgrep'],
        summary: {
          total: 3,
          critical: 1,
          high: 2,
          medium: 0,
          low: 0,
          info: 0,
        },
        error: null,
        startedAt: '2026-09-08T11:50:00Z',
        completedAt: '2026-09-08T11:52:15Z',
        duration: 135000,
        createdAt: '2026-09-08T11:50:00Z',
        updatedAt: '2026-09-08T11:52:15Z',
      };

      const html = renderToStaticMarkup(
        React.createElement(ScanCard, { scan })
      );
      expect(html).toContain('facebook/react');
      expect(html).toContain('main');
      expect(html).toContain('@a1b2c3d');
      expect(html).toContain('Completed');
      expect(html).toContain('Duration: 2m 15s');
      expect(html).toContain('/dashboard/scans/scan-123');
    });
  });
});
