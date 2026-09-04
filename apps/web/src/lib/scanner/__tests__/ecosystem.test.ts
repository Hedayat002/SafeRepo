import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import fs from 'fs/promises';
import path from 'path';
import os from 'os';
import {
  detectEcosystems,
  extractPackageLockCoordinates,
  extractRequirementsCoordinates,
  extractPipfileLockCoordinates,
  normalizePythonPackageName,
  normalizeNpmPackageName,
} from '../ecosystem';

describe('Ecosystem & Coordinate Extraction', () => {
  let tempDir: string;

  beforeEach(async () => {
    tempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'saferepo-eco-test-'));
  });

  afterEach(async () => {
    try {
      await fs.rm(tempDir, { recursive: true, force: true });
    } catch {
      // Ignore cleanup error
    }
  });

  describe('PEP 503 and npm Package Name Normalization', () => {
    it('normalizes Python package names according to PEP 503', () => {
      expect(normalizePythonPackageName('Foo_Bar.Baz')).toBe('foo-bar-baz');
      expect(normalizePythonPackageName('requests')).toBe('requests');
      expect(normalizePythonPackageName('os_v_2.0')).toBe('os-v-2-0');
      expect(normalizePythonPackageName('  Mixed.Separators__here--   ')).toBe('mixed-separators-here-');
    });

    it('normalizes npm package names preserving scopes', () => {
      expect(normalizeNpmPackageName('lodash')).toBe('lodash');
      expect(normalizeNpmPackageName('@types/node')).toBe('@types/node');
      expect(normalizeNpmPackageName('@Angular/Core')).toBe('@angular/core');
      expect(normalizeNpmPackageName('node_modules/lodash')).toBe('lodash');
      expect(normalizeNpmPackageName('node_modules/@types/node')).toBe('@types/node');
      expect(normalizeNpmPackageName('packages/foo/node_modules/bar')).toBe('bar');
    });
  });

  describe('Empty Workspace', () => {
    it('returns false for ecosystems and empty coordinates when no manifests exist', async () => {
      const result = await detectEcosystems(tempDir);
      expect(result.hasNode).toBe(false);
      expect(result.hasPython).toBe(false);
      expect(result.coordinates).toEqual([]);
      expect(result.manifests.node).toEqual([]);
      expect(result.manifests.python).toEqual([]);
    });
  });

  describe('package.json Detection & Range Security Invariant', () => {
    it('detects Node ecosystem presence from package.json without extracting ranges as coordinates', async () => {
      const packageJsonContent = JSON.stringify({
        name: 'test-app',
        dependencies: {
          lodash: '^4.17.20',
          express: '~4.18.2',
          semver: '*',
          debug: '>=4.0.0 <5.0.0',
        },
      });

      await fs.writeFile(path.join(tempDir, 'package.json'), packageJsonContent);

      const result = await detectEcosystems(tempDir);
      expect(result.hasNode).toBe(true);
      expect(result.manifests.node).toEqual(['package.json']);
      // Security invariant: Range specifiers in package.json MUST NOT be converted to exact versions
      expect(result.coordinates).toEqual([]);
    });
  });

  describe('package-lock.json Coordinate Extraction', () => {
    it('extracts exact resolved versions from package-lock v2/v3', () => {
      const lockfileContent = JSON.stringify({
        name: 'test-app',
        lockfileVersion: 3,
        packages: {
          '': { name: 'test-app', version: '1.0.0' },
          'node_modules/lodash': { version: '4.17.21' },
          'node_modules/@types/node': { version: '20.11.0' },
          'node_modules/express/node_modules/ms': { version: '2.1.3' },
          'node_modules/local-pkg': { version: 'file:../local' },
        },
      });

      const coords = extractPackageLockCoordinates(lockfileContent, 'package-lock.json');
      expect(coords).toHaveLength(3);
      expect(coords).toContainEqual({
        name: 'lodash',
        version: '4.17.21',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      });
      expect(coords).toContainEqual({
        name: '@types/node',
        version: '20.11.0',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      });
      expect(coords).toContainEqual({
        name: 'ms',
        version: '2.1.3',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      });
    });

    it('extracts exact resolved versions from package-lock v1 fallback', () => {
      const lockfileContent = JSON.stringify({
        name: 'test-v1-app',
        lockfileVersion: 1,
        dependencies: {
          lodash: { version: '4.17.19' },
          accepts: {
            version: '1.3.8',
            dependencies: {
              mime: { version: '1.6.0' },
            },
          },
        },
      });

      const coords = extractPackageLockCoordinates(lockfileContent, 'package-lock.json');
      expect(coords).toHaveLength(3);
      expect(coords).toContainEqual({
        name: 'lodash',
        version: '4.17.19',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      });
      expect(coords).toContainEqual({
        name: 'accepts',
        version: '1.3.8',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      });
      expect(coords).toContainEqual({
        name: 'mime',
        version: '1.6.0',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      });
    });

    it('deduplicates identical coordinates within the same lockfile', () => {
      const lockfileContent = JSON.stringify({
        lockfileVersion: 2,
        packages: {
          'node_modules/ms': { version: '2.1.2' },
          'node_modules/express/node_modules/ms': { version: '2.1.2' },
        },
      });

      const coords = extractPackageLockCoordinates(lockfileContent, 'package-lock.json');
      expect(coords).toHaveLength(1);
      expect(coords[0]).toEqual({
        name: 'ms',
        version: '2.1.2',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      });
    });

    it('safely handles malformed JSON without crashing', () => {
      const coords = extractPackageLockCoordinates('{ invalid json ...', 'package-lock.json');
      expect(coords).toEqual([]);
    });
  });

  describe('requirements.txt Coordinate Extraction', () => {
    it('extracts exact pinned versions (==) and normalizes names per PEP 503', () => {
      const requirementsContent = `
# Core dependencies
requests==2.31.0
Urllib3==1.26.15 # pinned
Flask-Cors==4.0.0; python_version >= '3.8'

# Ignored flags
-i https://pypi.org/simple
--extra-index-url https://custom.repo
-r base.txt

# Ranges that MUST NOT be resolved or invented
jinja2>=3.0.0
gunicorn~=20.1
pydantic<2.0.0
pytest
      `;

      const coords = extractRequirementsCoordinates(requirementsContent, 'requirements.txt');
      expect(coords).toHaveLength(3);
      expect(coords).toContainEqual({
        name: 'requests',
        version: '2.31.0',
        ecosystem: 'pypi',
        manifestPath: 'requirements.txt',
      });
      expect(coords).toContainEqual({
        name: 'urllib3',
        version: '1.26.15',
        ecosystem: 'pypi',
        manifestPath: 'requirements.txt',
      });
      expect(coords).toContainEqual({
        name: 'flask-cors',
        version: '4.0.0',
        ecosystem: 'pypi',
        manifestPath: 'requirements.txt',
      });
    });

    it('handles empty and whitespace-only requirements files', () => {
      const coords = extractRequirementsCoordinates('\n\n   \n# Only comments\n', 'requirements.txt');
      expect(coords).toEqual([]);
    });
  });

  describe('Pipfile.lock Coordinate Extraction', () => {
    it('extracts exact versions stripping leading == and normalizes names', () => {
      const pipfileContent = JSON.stringify({
        _meta: { hash: { sha256: 'abc' } },
        default: {
          requests: { version: '==2.31.0' },
          'Flask-Bcrypt': { version: '==1.0.1' },
        },
        develop: {
          pytest: { version: '==8.0.0' },
          black: { version: '>=23.0' }, // Range specifier should be skipped
        },
      });

      const coords = extractPipfileLockCoordinates(pipfileContent, 'Pipfile.lock');
      expect(coords).toHaveLength(3);
      expect(coords).toContainEqual({
        name: 'requests',
        version: '2.31.0',
        ecosystem: 'pypi',
        manifestPath: 'Pipfile.lock',
      });
      expect(coords).toContainEqual({
        name: 'flask-bcrypt',
        version: '1.0.1',
        ecosystem: 'pypi',
        manifestPath: 'Pipfile.lock',
      });
      expect(coords).toContainEqual({
        name: 'pytest',
        version: '8.0.0',
        ecosystem: 'pypi',
        manifestPath: 'Pipfile.lock',
      });
    });

    it('safely handles malformed Pipfile.lock JSON without crashing', () => {
      const coords = extractPipfileLockCoordinates('bad json', 'Pipfile.lock');
      expect(coords).toEqual([]);
    });
  });

  describe('Unsupported Formats Detection & Zero New Dependencies Rule', () => {
    it('detects yarn.lock, pnpm-lock.yaml, pyproject.toml, and poetry.lock for ecosystem presence without ad-hoc parsing', async () => {
      await fs.writeFile(path.join(tempDir, 'yarn.lock'), '# yarn lockfile v1\n');
      await fs.writeFile(path.join(tempDir, 'pnpm-lock.yaml'), 'lockfileVersion: 5.4\n');
      await fs.writeFile(path.join(tempDir, 'pyproject.toml'), '[tool.poetry]\nname = "test"\n');
      await fs.writeFile(path.join(tempDir, 'poetry.lock'), '# poetry.lock\n');

      const result = await detectEcosystems(tempDir);
      expect(result.hasNode).toBe(true);
      expect(result.hasPython).toBe(true);
      expect(result.manifests.node).toContain('yarn.lock');
      expect(result.manifests.node).toContain('pnpm-lock.yaml');
      expect(result.manifests.python).toContain('pyproject.toml');
      expect(result.manifests.python).toContain('poetry.lock');
      // No ad-hoc YAML/TOML parsing -> coordinates list must remain empty
      expect(result.coordinates).toEqual([]);
    });
  });

  describe('Polyglot Repositories', () => {
    it('detects both Node.js and Python ecosystems and extracts coordinates for both', async () => {
      const packageLock = JSON.stringify({
        lockfileVersion: 2,
        packages: {
          'node_modules/react': { version: '18.2.0' },
        },
      });
      const requirements = 'requests==2.31.0\n';

      await fs.writeFile(path.join(tempDir, 'package-lock.json'), packageLock);
      await fs.writeFile(path.join(tempDir, 'requirements.txt'), requirements);

      const result = await detectEcosystems(tempDir);
      expect(result.hasNode).toBe(true);
      expect(result.hasPython).toBe(true);
      expect(result.coordinates).toHaveLength(2);
      expect(result.coordinates).toContainEqual({
        name: 'react',
        version: '18.2.0',
        ecosystem: 'npm',
        manifestPath: 'package-lock.json',
      });
      expect(result.coordinates).toContainEqual({
        name: 'requests',
        version: '2.31.0',
        ecosystem: 'pypi',
        manifestPath: 'requirements.txt',
      });
    });
  });

  describe('Monorepo Traversal & Depth Limits', () => {
    it('discovers manifests in subdirectories up to depth 3 with normalized relative paths', async () => {
      // Depth 1
      const app1Dir = path.join(tempDir, 'apps', 'web');
      await fs.mkdir(app1Dir, { recursive: true });
      await fs.writeFile(
        path.join(app1Dir, 'package-lock.json'),
        JSON.stringify({
          lockfileVersion: 2,
          packages: { 'node_modules/next': { version: '14.1.0' } },
        })
      );

      // Depth 2
      const pkgDir = path.join(tempDir, 'packages', 'core', 'sub');
      await fs.mkdir(pkgDir, { recursive: true });
      await fs.writeFile(
        path.join(pkgDir, 'requirements.txt'),
        'fastapi==0.109.0\n'
      );

      const result = await detectEcosystems(tempDir, 3);
      expect(result.hasNode).toBe(true);
      expect(result.hasPython).toBe(true);
      expect(result.manifests.node).toContain('apps/web/package-lock.json');
      expect(result.manifests.python).toContain('packages/core/sub/requirements.txt');

      expect(result.coordinates).toContainEqual({
        name: 'next',
        version: '14.1.0',
        ecosystem: 'npm',
        manifestPath: 'apps/web/package-lock.json',
      });
      expect(result.coordinates).toContainEqual({
        name: 'fastapi',
        version: '0.109.0',
        ecosystem: 'pypi',
        manifestPath: 'packages/core/sub/requirements.txt',
      });
    });

    it('ignores manifests deeper than maxDepth (depth > 3)', async () => {
      const deepDir = path.join(tempDir, 'level1', 'level2', 'level3', 'level4');
      await fs.mkdir(deepDir, { recursive: true });
      await fs.writeFile(path.join(deepDir, 'package.json'), '{"name":"too-deep"}');

      const result = await detectEcosystems(tempDir, 3);
      expect(result.hasNode).toBe(false);
      expect(result.manifests.node).toEqual([]);
    });

    it('ignores designated directories (node_modules, .git, dist, build, venv, __pycache__)', async () => {
      const nodeModulesDir = path.join(tempDir, 'node_modules', 'dep');
      const gitDir = path.join(tempDir, '.git');
      const venvDir = path.join(tempDir, 'venv');

      await fs.mkdir(nodeModulesDir, { recursive: true });
      await fs.mkdir(gitDir, { recursive: true });
      await fs.mkdir(venvDir, { recursive: true });

      await fs.writeFile(path.join(nodeModulesDir, 'package.json'), '{"name":"dep"}');
      await fs.writeFile(path.join(gitDir, 'package.json'), '{"name":"git-fake"}');
      await fs.writeFile(path.join(venvDir, 'requirements.txt'), 'fake==1.0.0');

      const result = await detectEcosystems(tempDir);
      expect(result.hasNode).toBe(false);
      expect(result.hasPython).toBe(false);
      expect(result.coordinates).toEqual([]);
    });
  });

  describe('Security Boundaries & Symlink Protection', () => {
    it('detects and rejects malicious symlinks escaping workspace bounds', async () => {
      const outsideDir = await fs.mkdtemp(path.join(os.tmpdir(), 'saferepo-outside-'));
      await fs.writeFile(path.join(outsideDir, 'package.json'), '{"name":"escaped"}');

      try {
        // Attempt to create symlink pointing outside workspace
        await fs.symlink(outsideDir, path.join(tempDir, 'escaped-link'), 'dir');

        await expect(detectEcosystems(tempDir)).rejects.toThrow(
          /Malicious symlink escape detected/
        );
      } catch (err: unknown) {
        // If symlinks are restricted by OS without admin rights, verify safe handling
        if ((err as { code?: string }).code === 'EPERM') return;
        throw err;
      } finally {
        await fs.rm(outsideDir, { recursive: true, force: true });
      }
    });

    it('ensures all manifest paths are strictly workspace-relative without leading slashes or traversal', async () => {
      const subDir = path.join(tempDir, 'services', 'api');
      await fs.mkdir(subDir, { recursive: true });
      await fs.writeFile(path.join(subDir, 'package.json'), '{"name":"api"}');

      const result = await detectEcosystems(tempDir);
      for (const m of result.manifests.node) {
        expect(m.startsWith('/')).toBe(false);
        expect(m.startsWith('\\')).toBe(false);
        expect(m.includes('..')).toBe(false);
        expect(path.isAbsolute(m)).toBe(false);
      }
    });
  });
});
