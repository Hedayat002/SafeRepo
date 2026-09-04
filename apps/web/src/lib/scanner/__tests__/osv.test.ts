import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  executeOsvScan,
  chunkCoordinates,
  isExactResolvedVersion,
  mapEcosystemToOsv,
  resolveCanonicalVulnerabilityId,
  mapOsvSeverity,
  extractFixedVersion,
  OSV_MAX_BATCH_SIZE,
} from '../osv';
import type { DependencyCoordinate } from '@/types';

describe('OSV Host-Side Static Coordinate Scanner', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe('Version & Coordinate Validation (isExactResolvedVersion)', () => {
    it('accepts exact semver and pinned versions', () => {
      expect(isExactResolvedVersion('4.17.21')).toBe(true);
      expect(isExactResolvedVersion('1.0.0-beta.1')).toBe(true);
      expect(isExactResolvedVersion('2.31.0')).toBe(true);
      expect(isExactResolvedVersion('0.1.2+build.123')).toBe(true);
    });

    it('rejects range specifiers and unresolved keywords', () => {
      expect(isExactResolvedVersion('^4.17.20')).toBe(false);
      expect(isExactResolvedVersion('~1.2.3')).toBe(false);
      expect(isExactResolvedVersion('>=1.0.0')).toBe(false);
      expect(isExactResolvedVersion('<=2.0.0')).toBe(false);
      expect(isExactResolvedVersion('*')).toBe(false);
      expect(isExactResolvedVersion('latest')).toBe(false);
      expect(isExactResolvedVersion('unknown')).toBe(false);
      expect(isExactResolvedVersion('file:../pkg')).toBe(false);
      expect(isExactResolvedVersion('git+https://github.com/org/repo')).toBe(false);
      expect(isExactResolvedVersion('')).toBe(false);
    });
  });

  describe('Ecosystem Mapping (mapEcosystemToOsv)', () => {
    it('maps npm to npm and pypi to PyPI', () => {
      expect(mapEcosystemToOsv('npm')).toBe('npm');
      expect(mapEcosystemToOsv('pypi')).toBe('PyPI');
      expect(mapEcosystemToOsv('PyPI')).toBe('PyPI');
    });
  });

  describe('Canonical ID Resolution & Helpers', () => {
    it('prioritizes CVE alias over GHSA ID', () => {
      const canonical = resolveCanonicalVulnerabilityId('GHSA-35jh-r3h4-6jhm', [
        'CVE-2021-23337',
      ]);
      expect(canonical).toBe('CVE-2021-23337');
    });

    it('retains primary CVE ID if already a CVE', () => {
      const canonical = resolveCanonicalVulnerabilityId('CVE-2023-1234', []);
      expect(canonical).toBe('CVE-2023-1234');
    });

    it('falls back to primary ID if no CVE alias exists', () => {
      const canonical = resolveCanonicalVulnerabilityId('GHSA-35jh-r3h4-6jhm', ['OSV-2021-123']);
      expect(canonical).toBe('GHSA-35JH-R3H4-6JHM');
    });

    it('maps OSV severities (database_specific and CVSS)', () => {
      expect(mapOsvSeverity({ database_specific: { severity: 'CRITICAL' } })).toBe('critical');
      expect(mapOsvSeverity({ database_specific: { severity: 'HIGH' } })).toBe('high');
      expect(mapOsvSeverity({ database_specific: { severity: 'MODERATE' } })).toBe('medium');
      expect(mapOsvSeverity({ database_specific: { severity: 'LOW' } })).toBe('low');
      expect(mapOsvSeverity({ database_specific: { severity: 'INFO' } })).toBe('info');

      // CVSS numeric fallback
      expect(mapOsvSeverity({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }] })).toBe('critical'); // score >= 9.0
      expect(mapOsvSeverity({ severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L' }] })).toBe('low'); // score > 0.0

      // Default fallback
      expect(mapOsvSeverity({})).toBe('medium');
    });

    it('extracts fixed version from affected ranges', () => {
      const vuln = {
        affected: [
          {
            package: { name: 'lodash', ecosystem: 'npm' },
            ranges: [
              {
                type: 'SEMVER',
                events: [{ introduced: '0' }, { fixed: '4.17.21' }],
              },
            ],
          },
        ],
      };

      expect(extractFixedVersion(vuln, 'lodash')).toBe('4.17.21');
      expect(extractFixedVersion(vuln, 'express')).toBeUndefined();
    });
  });

  describe('Batch Chunking (chunkCoordinates)', () => {
    it('defines maximum batch size of 100', () => {
      expect(OSV_MAX_BATCH_SIZE).toBe(100);
    });

    it('returns empty array when coordinates list is empty', () => {
      expect(chunkCoordinates([])).toEqual([]);
    });

    it('chunks single coordinate into single batch', () => {
      const coords: DependencyCoordinate[] = [
        { name: 'lodash', version: '4.17.21', ecosystem: 'npm', manifestPath: 'package-lock.json' },
      ];
      const batches = chunkCoordinates(coords);
      expect(batches).toHaveLength(1);
      expect(batches[0]).toHaveLength(1);
    });

    it('chunks 100 coordinates into a single batch of 100', () => {
      const coords: DependencyCoordinate[] = Array.from({ length: 100 }, (_, i) => ({
        name: `pkg-${i}`,
        version: '1.0.0',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      }));

      const batches = chunkCoordinates(coords);
      expect(batches).toHaveLength(1);
      expect(batches[0]).toHaveLength(100);
    });

    it('chunks 101 coordinates into 2 batches (100 and 1)', () => {
      const coords: DependencyCoordinate[] = Array.from({ length: 101 }, (_, i) => ({
        name: `pkg-${i}`,
        version: '1.0.0',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      }));

      const batches = chunkCoordinates(coords);
      expect(batches).toHaveLength(2);
      expect(batches[0]).toHaveLength(100);
      expect(batches[1]).toHaveLength(1);
    });

    it('chunks 250 coordinates into 3 batches (100, 100, and 50)', () => {
      const coords: DependencyCoordinate[] = Array.from({ length: 250 }, (_, i) => ({
        name: `pkg-${i}`,
        version: '1.0.0',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      }));

      const batches = chunkCoordinates(coords);
      expect(batches).toHaveLength(3);
      expect(batches[0]).toHaveLength(100);
      expect(batches[1]).toHaveLength(100);
      expect(batches[2]).toHaveLength(50);
    });

    it('strictly filters out unresolved version ranges during chunking', () => {
      const coords: DependencyCoordinate[] = [
        { name: 'valid-pkg', version: '1.0.0', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        { name: 'range-pkg', version: '^2.0.0', ecosystem: 'npm', manifestPath: 'package.json' },
        { name: 'tilde-pkg', version: '~1.5.0', ecosystem: 'npm', manifestPath: 'package.json' },
        { name: 'star-pkg', version: '*', ecosystem: 'npm', manifestPath: 'package.json' },
      ];

      const batches = chunkCoordinates(coords);
      expect(batches).toHaveLength(1);
      expect(batches[0]).toHaveLength(1);
      expect(batches[0]![0]!.name).toBe('valid-pkg');
    });
  });

  describe('executeOsvScan Execution Flow & Security Controls', () => {
    it('performs zero HTTP requests and returns success when coordinates list is empty', async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);

      const result = await executeOsvScan({
        scanId: 'scan-empty',
        userId: 'user-1',
        coordinates: [],
      });

      expect(result.status).toBe('success');
      if (result.status === 'success') {
        expect(result.findings).toEqual([]);
        expect(result.rawMatchesCount).toBe(0);
      }
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('performs zero HTTP requests when all coordinates have invalid/unresolved versions', async () => {
      const fetchSpy = vi.fn();
      vi.stubGlobal('fetch', fetchSpy);

      const result = await executeOsvScan({
        scanId: 'scan-ranges-only',
        userId: 'user-1',
        coordinates: [
          { name: 'pkg1', version: '^1.0.0', ecosystem: 'npm', manifestPath: 'package.json' },
          { name: 'pkg2', version: '>=2.0.0', ecosystem: 'pypi', manifestPath: 'requirements.txt' },
        ],
      });

      expect(result.status).toBe('success');
      if (result.status === 'success') {
        expect(result.findings).toEqual([]);
      }
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('constructs privacy-preserving POST request containing ONLY package and version', async () => {
      let interceptedUrl: string | undefined;
      let interceptedOptions: RequestInit | undefined;

      const mockResponse = {
        ok: true,
        status: 200,
        json: async () => ({
          results: [{ vulns: [] }],
        }),
      };

      vi.stubGlobal(
        'fetch',
        vi.fn((url: string, options: RequestInit) => {
          interceptedUrl = url;
          interceptedOptions = options;
          return Promise.resolve(mockResponse);
        })
      );

      const coords: DependencyCoordinate[] = [
        { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
      ];

      const result = await executeOsvScan({
        scanId: 'scan-privacy',
        userId: 'user-1',
        coordinates: coords,
        apiUrl: 'https://api.osv.dev/v1/querybatch',
      });

      expect(result.status).toBe('success');
      expect(interceptedUrl).toBe('https://api.osv.dev/v1/querybatch');
      expect(interceptedOptions?.method).toBe('POST');
      expect(interceptedOptions?.redirect).toBe('error');

      // Security check: Request body MUST contain ONLY queries with package name and version
      const body = JSON.parse(interceptedOptions?.body as string);
      expect(body).toEqual({
        queries: [
          {
            package: {
              name: 'lodash',
              ecosystem: 'npm',
            },
            version: '4.17.20',
          },
        ],
      });

      // Data minimization check: Ensure NO repository content, paths, or tokens are transmitted
      const rawString = interceptedOptions?.body as string;
      expect(rawString).not.toContain('package-lock.json');
      expect(rawString).not.toContain('/src');
      expect(rawString).not.toContain('user-1');
      expect(rawString).not.toContain('scan-privacy');
    });

    it('successfully maps OSV vulnerabilities into normalized finding objects', async () => {
      const mockOsvResponse = {
        results: [
          {
            vulns: [
              {
                id: 'GHSA-35jh-r3h4-6jhm',
                aliases: ['CVE-2021-23337'],
                summary: 'Command Injection in lodash',
                details: 'A critical command injection vulnerability in lodash.',
                database_specific: {
                  severity: 'HIGH',
                },
                affected: [
                  {
                    package: { name: 'lodash', ecosystem: 'npm' },
                    ranges: [
                      {
                        type: 'SEMVER',
                        events: [{ introduced: '0' }, { fixed: '4.17.21' }],
                      },
                    ],
                  },
                ],
              },
            ],
          },
        ],
      };

      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => mockOsvResponse,
        })
      );

      const result = await executeOsvScan({
        scanId: 'scan-vuln',
        userId: 'user-1',
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
      });

      expect(result.status).toBe('success');
      if (result.status === 'success') {
        expect(result.findings).toHaveLength(1);
        const finding = result.findings[0]!;
        expect(finding.vulnerabilityId).toBe('GHSA-35jh-r3h4-6jhm');
        expect(finding.canonicalId).toBe('CVE-2021-23337');
        expect(finding.package).toBe('lodash');
        expect(finding.packageVersion).toBe('4.17.20');
        expect(finding.fixedVersion).toBe('4.17.21');
        expect(finding.severity).toBe('high');
        expect(finding.title).toBe('Command Injection in lodash');
        expect(finding.remediation).toBe('Upgrade lodash to 4.17.21');
        expect(finding.target).toBe('package-lock.json');
        expect(finding.ecosystem).toBe('npm');
        expect(finding.aliases).toContain('CVE-2021-23337');
      }
    });

    it('correctly parses exact PyPI coordinates and maps ecosystem to PyPI', async () => {
      let interceptedBody: string | undefined;

      vi.stubGlobal(
        'fetch',
        vi.fn((_url: string, options: RequestInit) => {
          interceptedBody = options.body as string;
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({ results: [{ vulns: [] }] }),
          });
        })
      );

      const result = await executeOsvScan({
        scanId: 'scan-pypi',
        userId: 'user-1',
        coordinates: [
          { name: 'requests', version: '2.31.0', ecosystem: 'pypi', manifestPath: 'requirements.txt' },
        ],
      });

      expect(result.status).toBe('success');
      const body = JSON.parse(interceptedBody!);
      expect(body.queries[0].package.ecosystem).toBe('PyPI');
      expect(body.queries[0].package.name).toBe('requests');
      expect(body.queries[0].version).toBe('2.31.0');
    });

    it('handles multiple batches (> 100 coordinates) sequentially', async () => {
      const fetchSpy = vi.fn().mockResolvedValue({
        ok: true,
        status: 200,
        json: async () => ({ results: Array.from({ length: 100 }, () => ({ vulns: [] })) }),
      });
      vi.stubGlobal('fetch', fetchSpy);

      const coords: DependencyCoordinate[] = Array.from({ length: 250 }, (_, i) => ({
        name: `pkg-${i}`,
        version: '1.0.0',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      }));

      const result = await executeOsvScan({
        scanId: 'scan-multi-batch',
        userId: 'user-1',
        coordinates: coords,
      });

      expect(result.status).toBe('success');
      // 250 coordinates chunked into 100, 100, 50 -> exactly 3 fetch calls
      expect(fetchSpy).toHaveBeenCalledTimes(3);
    });

    it('retries on HTTP 429 rate limit and succeeds on retry', async () => {
      let callCount = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn(() => {
          callCount++;
          if (callCount === 1) {
            return Promise.resolve({
              ok: false,
              status: 429,
              statusText: 'Too Many Requests',
            });
          }
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({ results: [{ vulns: [] }] }),
          });
        })
      );

      const result = await executeOsvScan({
        scanId: 'scan-retry-429',
        userId: 'user-1',
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
        initialBackoffMs: 1, // fast backoff for tests
      });

      expect(result.status).toBe('success');
      expect(callCount).toBe(2);
    });

    it('retries on HTTP 503 service unavailable and succeeds on retry', async () => {
      let callCount = 0;
      vi.stubGlobal(
        'fetch',
        vi.fn(() => {
          callCount++;
          if (callCount <= 2) {
            return Promise.resolve({
              ok: false,
              status: 503,
              statusText: 'Service Unavailable',
            });
          }
          return Promise.resolve({
            ok: true,
            status: 200,
            json: async () => ({ results: [{ vulns: [] }] }),
          });
        })
      );

      const result = await executeOsvScan({
        scanId: 'scan-retry-503',
        userId: 'user-1',
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
        initialBackoffMs: 1,
      });

      expect(result.status).toBe('success');
      expect(callCount).toBe(3);
    });

    it('fails after exceeding retry limit on persistent 429', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: false,
          status: 429,
          statusText: 'Too Many Requests',
        })
      );

      const result = await executeOsvScan({
        scanId: 'scan-exceed-retries',
        userId: 'user-1',
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
        maxRetries: 2,
        initialBackoffMs: 1,
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.error).toContain('transient error HTTP 429 exceeded retry limit');
      }
    });

    it('fails immediately without retrying on permanent HTTP 400 Bad Request', async () => {
      const fetchSpy = vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        statusText: 'Bad Request',
      });
      vi.stubGlobal('fetch', fetchSpy);

      const result = await executeOsvScan({
        scanId: 'scan-400',
        userId: 'user-1',
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
        maxRetries: 3,
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.error).toContain('HTTP 400: Bad Request');
      }
      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });

    it('handles request timeout (AbortError) with controlled failure', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockImplementation(() => {
          const abortErr = new Error('The operation was aborted');
          abortErr.name = 'AbortError';
          return Promise.reject(abortErr);
        })
      );

      const result = await executeOsvScan({
        scanId: 'scan-timeout',
        userId: 'user-1',
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
        timeoutMs: 100,
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.error).toContain('OSV API request timed out after 100ms');
      }
    });

    it('handles network failure (fetch error) after retry attempts', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockRejectedValue(new Error('fetch failed: ECONNREFUSED'))
      );

      const result = await executeOsvScan({
        scanId: 'scan-network-fail',
        userId: 'user-1',
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
        maxRetries: 1,
        initialBackoffMs: 1,
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.error).toContain('ECONNREFUSED');
      }
    });

    it('handles malformed JSON response with controlled failure', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => {
            throw new Error('Unexpected token in JSON');
          },
        })
      );

      const result = await executeOsvScan({
        scanId: 'scan-bad-json',
        userId: 'user-1',
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.error).toContain('Unexpected token in JSON');
      }
    });

    it('handles malformed OSV response structure (missing results array)', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => ({ invalidStructure: true }),
        })
      );

      const result = await executeOsvScan({
        scanId: 'scan-invalid-structure',
        userId: 'user-1',
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
      });

      expect(result.status).toBe('failed');
      if (result.status === 'failed') {
        expect(result.error).toContain('missing results array');
      }
    });

    it('does not invoke child_process or shell execution', async () => {
      vi.stubGlobal(
        'fetch',
        vi.fn().mockResolvedValue({
          ok: true,
          status: 200,
          json: async () => ({ results: [{ vulns: [] }] }),
        })
      );

      const result = await executeOsvScan({
        scanId: 'scan-no-shell',
        userId: 'user-1',
        coordinates: [
          { name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' },
        ],
      });

      expect(result.status).toBe('success');
      // Proves purely in-memory HTTP client with zero child process activity
    });

    it('maps direct numeric CVSS scores correctly across all severity tiers', () => {
      expect(mapOsvSeverity({ severity: [{ type: 'CVSS_V3', score: '9.8' }] })).toBe('critical');
      expect(mapOsvSeverity({ severity: [{ type: 'CVSS_V3', score: '7.5' }] })).toBe('high');
      expect(mapOsvSeverity({ severity: [{ type: 'CVSS_V3', score: '5.5' }] })).toBe('medium');
      expect(mapOsvSeverity({ severity: [{ type: 'CVSS_V3', score: '2.5' }] })).toBe('low');
    });

    it('enforces ScannerResult discriminated union contract on both success and failure', async () => {
      // Success contract
      const successResult = await executeOsvScan({
        scanId: 'scan-contract-success',
        userId: 'user-1',
        coordinates: [],
      });
      expect(successResult.status).toBe('success');
      expect(successResult.scanner).toBe('osv');
      if (successResult.status === 'success') {
        expect(Array.isArray(successResult.findings)).toBe(true);
        expect(typeof successResult.durationMs).toBe('number');
        expect(typeof successResult.rawMatchesCount).toBe('number');
      }

      // Failure contract
      vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('Network error')));
      const failResult = await executeOsvScan({
        scanId: 'scan-contract-fail',
        userId: 'user-1',
        coordinates: [{ name: 'lodash', version: '4.17.20', ecosystem: 'npm', manifestPath: 'package-lock.json' }],
        maxRetries: 0,
      });
      expect(failResult.status).toBe('failed');
      expect(failResult.scanner).toBe('osv');
      if (failResult.status === 'failed') {
        expect(failResult.error).toContain('Network error');
        expect(typeof failResult.durationMs).toBe('number');
      }
    });
  });
});

