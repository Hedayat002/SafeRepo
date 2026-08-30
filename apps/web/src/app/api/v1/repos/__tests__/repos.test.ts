import { describe, it, expect, beforeEach, vi } from 'vitest';
import { NextRequest } from 'next/server';
import { User } from '@/models/user';
import { Session } from '@/models/session';
import { GET as getReposHandler } from '@/app/api/v1/repos/route';
import { GET as getRepoDetailHandler } from '@/app/api/v1/repos/[owner]/[name]/route';
import * as sessionModule from '@/lib/session';
import * as githubModule from '@/lib/github';

describe('Repos API Routes', () => {
  beforeEach(async () => {
    await User.deleteMany({});
    await Session.deleteMany({});
    vi.restoreAllMocks();
  });

  describe('GET /api/v1/repos', () => {
    it('should return 401 when unauthenticated', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(undefined);

      const request = new NextRequest('http://localhost:3000/api/v1/repos');
      const response = await getReposHandler(request);
      expect(response.status).toBe(401);

      const json = await response.json();
      expect(json.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 400 on invalid query params', async () => {
      const user = await User.create({ githubId: 'repo-user-1', username: 'repouser1' });
      const session = await Session.create({
        sessionId: 'repo-sess-1',
        userId: user._id,
        githubAccessToken: 'ghu_token',
        expiresAt: new Date(Date.now() + 86400000),
      });

      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session.sessionId);

      const request = new NextRequest('http://localhost:3000/api/v1/repos?page=-5');
      const response = await getReposHandler(request);
      expect(response.status).toBe(400);

      const json = await response.json();
      expect(json.error.code).toBe('VALIDATION_ERROR');
    });

    it('should return repository list when authenticated and valid query', async () => {
      const user = await User.create({ githubId: 'repo-user-2', username: 'repouser2' });
      const session = await Session.create({
        sessionId: 'repo-sess-2',
        userId: user._id,
        githubAccessToken: 'ghu_token',
        expiresAt: new Date(Date.now() + 86400000),
      });

      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session.sessionId);
      vi.spyOn(githubModule, 'getUserRepos').mockResolvedValue({
        repos: [
          {
            id: 123456,
            name: 'my-repo',
            full_name: 'repouser2/my-repo',
            owner: { login: 'repouser2', avatar_url: 'https://avatar.url' },
            private: false,
            html_url: 'https://github.com/repouser2/my-repo',
            description: 'My awesome repo',
            fork: false,
            language: 'TypeScript',
            default_branch: 'main',
            stargazers_count: 10,
            forks_count: 2,
            open_issues_count: 0,
            created_at: '2026-01-01T00:00:00Z',
            updated_at: '2026-01-02T00:00:00Z',
            pushed_at: '2026-01-02T00:00:00Z',
          },
        ],
        totalCount: 1,
      });

      const request = new NextRequest('http://localhost:3000/api/v1/repos?page=1&per_page=30');
      const response = await getReposHandler(request);
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.data).toHaveLength(1);
      expect(json.data[0].name).toBe('my-repo');
      expect(json.meta.total).toBe(1);
      expect(json.meta.page).toBe(1);
      expect(json.meta.limit).toBe(30);
    });
  });

  describe('GET /api/v1/repos/:owner/:name', () => {
    it('should return 401 when unauthenticated', async () => {
      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(undefined);

      const request = new NextRequest('http://localhost:3000/api/v1/repos/facebook/react');
      const response = await getRepoDetailHandler(request, {
        params: Promise.resolve({ owner: 'facebook', name: 'react' }),
      });
      expect(response.status).toBe(401);

      const json = await response.json();
      expect(json.error.code).toBe('UNAUTHORIZED');
    });

    it('should return 404 when repository is not found', async () => {
      const user = await User.create({ githubId: 'repo-user-3', username: 'repouser3' });
      const session = await Session.create({
        sessionId: 'repo-sess-3',
        userId: user._id,
        githubAccessToken: 'ghu_token',
        expiresAt: new Date(Date.now() + 86400000),
      });

      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session.sessionId);
      vi.spyOn(githubModule, 'getRepo').mockResolvedValue(null);

      const request = new NextRequest('http://localhost:3000/api/v1/repos/nonexistent/repo');
      const response = await getRepoDetailHandler(request, {
        params: Promise.resolve({ owner: 'nonexistent', name: 'repo' }),
      });
      expect(response.status).toBe(404);

      const json = await response.json();
      expect(json.error.code).toBe('NOT_FOUND');
    });

    it('should return repository details when authenticated and found', async () => {
      const user = await User.create({ githubId: 'repo-user-4', username: 'repouser4' });
      const session = await Session.create({
        sessionId: 'repo-sess-4',
        userId: user._id,
        githubAccessToken: 'ghu_token',
        expiresAt: new Date(Date.now() + 86400000),
      });

      vi.spyOn(sessionModule, 'getSessionIdFromCookies').mockResolvedValue(session.sessionId);
      vi.spyOn(githubModule, 'getRepo').mockResolvedValue({
        id: 9999,
        name: 'react',
        full_name: 'facebook/react',
        owner: { login: 'facebook', avatar_url: 'https://facebook.url' },
        private: false,
        html_url: 'https://github.com/facebook/react',
        description: 'React library',
        fork: false,
        language: 'JavaScript',
        default_branch: 'main',
        stargazers_count: 200000,
        forks_count: 40000,
        open_issues_count: 500,
        created_at: '2013-05-24T00:00:00Z',
        updated_at: '2026-08-24T00:00:00Z',
        pushed_at: '2026-08-24T00:00:00Z',
      });

      const request = new NextRequest('http://localhost:3000/api/v1/repos/facebook/react');
      const response = await getRepoDetailHandler(request, {
        params: Promise.resolve({ owner: 'facebook', name: 'react' }),
      });
      expect(response.status).toBe(200);

      const json = await response.json();
      expect(json.data.name).toBe('react');
      expect(json.data.owner).toBe('facebook');
      expect(json.data.stargazersCount).toBe(200000);
    });
  });
});
