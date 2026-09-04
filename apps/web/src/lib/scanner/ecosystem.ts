import fs from 'fs/promises';
import path from 'path';
import type { DependencyCoordinate, EcosystemDetectionResult } from '@/types';
import { logger } from '@/lib/logger';

/** Directories to ignore during recursive filesystem traversal */
const IGNORED_DIRECTORIES = new Set([
  'node_modules',
  '.git',
  'dist',
  'build',
  'venv',
  '__pycache__',
  '.next',
  '.venv',
  'env',
  '.turbo',
  'coverage',
]);

/** Known manifest filenames categorized by ecosystem */
const NODE_MANIFEST_FILES = new Set([
  'package-lock.json',
  'package.json',
  'yarn.lock',
  'pnpm-lock.yaml',
]);

const PYTHON_MANIFEST_FILES = new Set([
  'requirements.txt',
  'Pipfile.lock',
  'pyproject.toml',
  'poetry.lock',
]);

/**
 * Normalizes Python package names according to PEP 503:
 * Converts to lowercase and replaces runs of [-_.]+ with a single dash.
 */
export function normalizePythonPackageName(name: string): string {
  return name
    .trim()
    .toLowerCase()
    .replace(/[-_.]+/g, '-');
}

/**
 * Normalizes npm package names:
 * Preserves scope (@scope/pkg) and converts to lowercase.
 */
export function normalizeNpmPackageName(name: string): string {
  const trimmed = name.trim().toLowerCase();
  // Strip leading node_modules/ if present
  const nmIndex = trimmed.lastIndexOf('node_modules/');
  if (nmIndex !== -1) {
    return trimmed.substring(nmIndex + 'node_modules/'.length);
  }
  return trimmed;
}

/**
 * Statically extracts exact dependency coordinates from package-lock.json (Lockfile v1, v2, and v3).
 * Never executes npm or lifecycle scripts.
 */
export function extractPackageLockCoordinates(
  content: string,
  manifestPath: string
): DependencyCoordinate[] {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content) as Record<string, unknown>;
  } catch {
    logger.warn({ manifestPath }, 'Malformed package-lock.json; skipping coordinate extraction');
    return [];
  }

  const coordinates: DependencyCoordinate[] = [];
  const seenKeys = new Set<string>();

  const addCoordinate = (rawName: string, rawVersion: unknown) => {
    if (typeof rawVersion !== 'string') return;
    const version = rawVersion.trim();
    // Verify it is an exact version, not a git repo, file path, or range
    if (!version || version.startsWith('file:') || version.startsWith('git') || version.startsWith('http')) {
      return;
    }

    const name = normalizeNpmPackageName(rawName);
    if (!name) return;

    const dedupeKey = `npm:${name}:${version}:${manifestPath}`;
    if (!seenKeys.has(dedupeKey)) {
      seenKeys.add(dedupeKey);
      coordinates.push({
        name,
        version,
        ecosystem: 'npm',
        manifestPath,
      });
    }
  };

  // Lockfile v2 / v3: 'packages' dictionary
  if (parsed.packages && typeof parsed.packages === 'object') {
    const packages = parsed.packages as Record<string, { version?: unknown }>;
    for (const [pkgPath, pkgData] of Object.entries(packages)) {
      // Key "" represents the root package itself
      if (pkgPath === '' || !pkgData) continue;

      // Extract package name from path (e.g. "node_modules/lodash" or "node_modules/@types/node")
      const name = normalizeNpmPackageName(pkgPath);
      addCoordinate(name, pkgData.version);
    }
  }

  // Lockfile v1 fallback (or nested dependencies in v2): 'dependencies' dictionary
  if (coordinates.length === 0 && parsed.dependencies && typeof parsed.dependencies === 'object') {
    const traverseV1 = (deps: Record<string, unknown>) => {
      for (const [pkgName, depData] of Object.entries(deps)) {
        if (!depData || typeof depData !== 'object') continue;
        const dep = depData as { version?: unknown; dependencies?: Record<string, unknown> };

        addCoordinate(pkgName, dep.version);

        if (dep.dependencies && typeof dep.dependencies === 'object') {
          traverseV1(dep.dependencies);
        }
      }
    };

    traverseV1(parsed.dependencies as Record<string, unknown>);
  }

  return coordinates;
}

/**
 * Statically extracts exact dependency coordinates from requirements.txt.
 * Only exact equality (`pkg==1.2.3`) is accepted.
 * Ranges (>=, <=, ~=, >, <, !=) and unpinned packages are strictly skipped without inventing versions.
 */
export function extractRequirementsCoordinates(
  content: string,
  manifestPath: string
): DependencyCoordinate[] {
  const coordinates: DependencyCoordinate[] = [];
  const seenKeys = new Set<string>();
  const lines = content.split(/\r?\n/);

  // Exact pinned version regex: package_name == 1.2.3
  const exactPinnedRegex = /^([a-zA-Z0-9_\-\.]+)\s*==\s*([a-zA-Z0-9_\-\.\+]+)$/;

  for (const rawLine of lines) {
    let line = rawLine.trim();

    // Ignore empty lines, full-line comments, and pip option flags (-r, -i, -f, --extra-index-url)
    if (!line || line.startsWith('#') || line.startsWith('-')) {
      continue;
    }

    // Strip inline comments
    if (line.includes('#')) {
      line = line.split('#')[0]!.trim();
    }

    // Strip environment markers (e.g. "package==1.2.3; python_version >= '3.8'")
    if (line.includes(';')) {
      line = line.split(';')[0]!.trim();
    }

    if (!line) continue;

    const match = exactPinnedRegex.exec(line);
    if (match) {
      const rawName = match[1]!;
      const version = match[2]!.trim();
      const name = normalizePythonPackageName(rawName);

      const dedupeKey = `pypi:${name}:${version}:${manifestPath}`;
      if (!seenKeys.has(dedupeKey)) {
        seenKeys.add(dedupeKey);
        coordinates.push({
          name,
          version,
          ecosystem: 'pypi',
          manifestPath,
        });
      }
    }
    // Any line with version ranges (>=, <=, ~=, >, <, !=) or unpinned specifier is intentionally skipped
  }

  return coordinates;
}

/**
 * Statically extracts exact dependency coordinates from Pipfile.lock.
 * Never executes python or pipenv.
 */
export function extractPipfileLockCoordinates(
  content: string,
  manifestPath: string
): DependencyCoordinate[] {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(content) as Record<string, unknown>;
  } catch {
    logger.warn({ manifestPath }, 'Malformed Pipfile.lock; skipping coordinate extraction');
    return [];
  }

  const coordinates: DependencyCoordinate[] = [];
  const seenKeys = new Set<string>();

  const sections = [parsed.default, parsed.develop];

  for (const section of sections) {
    if (!section || typeof section !== 'object') continue;

    for (const [rawName, depData] of Object.entries(section as Record<string, unknown>)) {
      if (!depData || typeof depData !== 'object') continue;
      const dep = depData as { version?: unknown };

      if (typeof dep.version !== 'string') continue;
      let version = dep.version.trim();

      // Pipfile.lock versions start with == (e.g. "==2.25.1")
      if (version.startsWith('==')) {
        version = version.substring(2).trim();
      }

      // Verify exact version format (no wildcards or range specifiers)
      if (!/^[a-zA-Z0-9_\-\.\+]+$/.test(version)) {
        continue;
      }

      const name = normalizePythonPackageName(rawName);
      const dedupeKey = `pypi:${name}:${version}:${manifestPath}`;

      if (!seenKeys.has(dedupeKey)) {
        seenKeys.add(dedupeKey);
        coordinates.push({
          name,
          version,
          ecosystem: 'pypi',
          manifestPath,
        });
      }
    }
  }

  return coordinates;
}

/**
 * Discovers manifest files in the workspace up to maxDepth (default 3),
 * skipping ignored directories and enforcing symlink boundary checks.
 */
async function discoverManifestFiles(
  workspacePath: string,
  maxDepth = 3
): Promise<{ manifestPath: string; fullPath: string; filename: string }[]> {
  const resolvedBase = await fs.realpath(workspacePath);
  const discovered: { manifestPath: string; fullPath: string; filename: string }[] = [];

  async function traverse(currentDir: string, currentDepth: number): Promise<void> {
    if (currentDepth > maxDepth) return;

    let entries;
    try {
      entries = await fs.readdir(currentDir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(currentDir, entry.name);

      // Symlink escape validation
      if (entry.isSymbolicLink()) {
        try {
          const resolvedTarget = await fs.realpath(fullPath);
          if (
            !resolvedTarget.startsWith(resolvedBase + path.sep) &&
            resolvedTarget !== resolvedBase
          ) {
            throw new Error(
              `Malicious symlink escape detected: ${entry.name} resolves to ${resolvedTarget}`
            );
          }
        } catch (err: unknown) {
          const msg = err instanceof Error ? err.message : String(err);
          if (msg.includes('Malicious symlink escape')) {
            throw err;
          }
          // Broken internal symlink — safely ignore
          continue;
        }
      }

      if (entry.isDirectory()) {
        if (!IGNORED_DIRECTORIES.has(entry.name) && currentDepth < maxDepth) {
          await traverse(fullPath, currentDepth + 1);
        }
      } else if (entry.isFile() || entry.isSymbolicLink()) {
        const isNodeManifest = NODE_MANIFEST_FILES.has(entry.name);
        const isPythonManifest = PYTHON_MANIFEST_FILES.has(entry.name);

        if (isNodeManifest || isPythonManifest) {
          const manifestPath = path
            .relative(resolvedBase, fullPath)
            .replace(/\\/g, '/');

          // Prevent traversal escapes
          if (!manifestPath.startsWith('..') && !path.isAbsolute(manifestPath)) {
            discovered.push({
              manifestPath,
              fullPath,
              filename: entry.name,
            });
          }
        }
      }
    }
  }

  await traverse(resolvedBase, 0);
  return discovered;
}

/**
 * Performs static ecosystem detection and exact coordinate extraction
 * across an acquired workspace without executing any repository code.
 *
 * Invariant: Never resolves or invents versions for dependency ranges.
 */
export async function detectEcosystems(
  workspacePath: string,
  maxDepth = 3
): Promise<EcosystemDetectionResult> {
  const manifests = await discoverManifestFiles(workspacePath, maxDepth);

  const result: EcosystemDetectionResult = {
    hasNode: false,
    hasPython: false,
    coordinates: [],
    manifests: {
      node: [],
      python: [],
    },
  };

  const seenCoordinateKeys = new Set<string>();

  for (const manifest of manifests) {
    const { manifestPath, fullPath, filename } = manifest;

    if (NODE_MANIFEST_FILES.has(filename)) {
      result.hasNode = true;
      result.manifests.node.push(manifestPath);

      if (filename === 'package-lock.json') {
        try {
          const content = await fs.readFile(fullPath, 'utf-8');
          const coords = extractPackageLockCoordinates(content, manifestPath);
          for (const coord of coords) {
            const key = `${coord.ecosystem}:${coord.name}:${coord.version}:${coord.manifestPath}`;
            if (!seenCoordinateKeys.has(key)) {
              seenCoordinateKeys.add(key);
              result.coordinates.push(coord);
            }
          }
        } catch (err) {
          logger.warn({ manifestPath, err }, 'Failed to read package-lock.json');
        }
      }
      // Note: package.json, yarn.lock, pnpm-lock.yaml are detected as hasNode,
      // but exact OSV coordinates are NOT extracted to avoid range estimation or ad-hoc YAML parsing.
    }

    if (PYTHON_MANIFEST_FILES.has(filename)) {
      result.hasPython = true;
      result.manifests.python.push(manifestPath);

      if (filename === 'requirements.txt') {
        try {
          const content = await fs.readFile(fullPath, 'utf-8');
          const coords = extractRequirementsCoordinates(content, manifestPath);
          for (const coord of coords) {
            const key = `${coord.ecosystem}:${coord.name}:${coord.version}:${coord.manifestPath}`;
            if (!seenCoordinateKeys.has(key)) {
              seenCoordinateKeys.add(key);
              result.coordinates.push(coord);
            }
          }
        } catch (err) {
          logger.warn({ manifestPath, err }, 'Failed to read requirements.txt');
        }
      } else if (filename === 'Pipfile.lock') {
        try {
          const content = await fs.readFile(fullPath, 'utf-8');
          const coords = extractPipfileLockCoordinates(content, manifestPath);
          for (const coord of coords) {
            const key = `${coord.ecosystem}:${coord.name}:${coord.version}:${coord.manifestPath}`;
            if (!seenCoordinateKeys.has(key)) {
              seenCoordinateKeys.add(key);
              result.coordinates.push(coord);
            }
          }
        } catch (err) {
          logger.warn({ manifestPath, err }, 'Failed to read Pipfile.lock');
        }
      }
      // Note: pyproject.toml and poetry.lock are detected as hasPython,
      // but exact OSV coordinates are NOT extracted to avoid ad-hoc TOML parsing.
    }
  }

  return result;
}
