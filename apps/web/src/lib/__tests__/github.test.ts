import { describe, it, expect, vi, beforeEach } from 'vitest';
import { getGitHubAppAuthUrl } from '@/lib/github';

/**
 * GitHub App helper tests.
 * All GitHub API calls are mocked — no real credentials needed.
 */

describe('GitHub Helpers', () => {
  beforeEach(() => {
    process.env.GITHUB_CLIENT_ID = 'test-client-id';
    process.env.GITHUB_CLIENT_SECRET = 'test-client-secret';
    process.env.NEXT_PUBLIC_APP_URL = 'http://localhost:3000';
  });

  describe('getGitHubAppAuthUrl', () => {
    it('should generate a valid GitHub authorization URL', () => {
      const url = getGitHubAppAuthUrl('test-state-123');

      expect(url).toContain('https://github.com/login/oauth/authorize');
      expect(url).toContain('client_id=test-client-id');
      expect(url).toContain('state=test-state-123');
      expect(url).toContain('redirect_uri=');
      expect(url).toContain('scope=read%3Auser+user%3Aemail');
    });

    it('should include the correct callback URL', () => {
      const url = getGitHubAppAuthUrl('state');

      expect(url).toContain(
        encodeURIComponent('http://localhost:3000/api/v1/auth/github/callback')
      );
    });

    it('should throw if GITHUB_CLIENT_ID is not set', () => {
      delete process.env.GITHUB_CLIENT_ID;

      expect(() => getGitHubAppAuthUrl('state')).toThrow('GITHUB_CLIENT_ID is not configured');
    });
  });

  describe('exchangeCodeForToken', () => {
    it('should exchange code for access token', async () => {
      const { exchangeCodeForToken } = await import('@/lib/github');

      const mockResponse = {
        ok: true,
        json: async () => ({ access_token: 'ghu_mocked_token' }),
      };
      global.fetch = vi.fn().mockResolvedValueOnce(mockResponse);

      const token = await exchangeCodeForToken('test-code');

      expect(token).toBe('ghu_mocked_token');
      expect(fetch).toHaveBeenCalledWith(
        'https://github.com/login/oauth/access_token',
        expect.objectContaining({
          method: 'POST',
          headers: expect.objectContaining({
            Accept: 'application/json',
          }),
        })
      );
    });

    it('should throw on failed token exchange', async () => {
      const { exchangeCodeForToken } = await import('@/lib/github');

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 400,
      });

      await expect(exchangeCodeForToken('bad-code')).rejects.toThrow(
        'Failed to exchange authorization code for token'
      );
    });

    it('should throw on error response from GitHub', async () => {
      const { exchangeCodeForToken } = await import('@/lib/github');

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => ({ error: 'bad_verification_code' }),
      });

      await expect(exchangeCodeForToken('expired-code')).rejects.toThrow(
        'GitHub OAuth error: bad_verification_code'
      );
    });
  });

  describe('getGitHubUser', () => {
    it('should fetch user profile', async () => {
      const { getGitHubUser } = await import('@/lib/github');

      const mockUser = {
        id: 12345,
        login: 'testuser',
        name: 'Test User',
        email: 'test@example.com',
        avatar_url: 'https://avatars.example.com/12345',
      };

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => mockUser,
      });

      const user = await getGitHubUser('ghu_test_token');

      expect(user.id).toBe(12345);
      expect(user.login).toBe('testuser');
      expect(fetch).toHaveBeenCalledWith(
        'https://api.github.com/user',
        expect.objectContaining({
          headers: expect.objectContaining({
            Authorization: 'Bearer ghu_test_token',
          }),
        })
      );
    });

    it('should throw on failed user fetch', async () => {
      const { getGitHubUser } = await import('@/lib/github');

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 401,
      });

      await expect(getGitHubUser('bad-token')).rejects.toThrow(
        'Failed to fetch GitHub user profile'
      );
    });
  });

  describe('getUserRepos', () => {
    it('should fetch user repositories', async () => {
      const { getUserRepos } = await import('@/lib/github');

      const mockRepos = [
        {
          id: 1,
          name: 'repo1',
          full_name: 'user/repo1',
          owner: { login: 'user', avatar_url: 'https://example.com/avatar' },
          private: false,
          html_url: 'https://github.com/user/repo1',
          description: 'Test repo',
          fork: false,
          language: 'TypeScript',
          default_branch: 'main',
          stargazers_count: 10,
          forks_count: 2,
          open_issues_count: 1,
          created_at: '2024-01-01T00:00:00Z',
          updated_at: '2024-06-01T00:00:00Z',
          pushed_at: '2024-06-01T00:00:00Z',
        },
      ];

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => mockRepos,
        headers: new Headers(),
      });

      const { repos, totalCount } = await getUserRepos('ghu_token', 1, 30);

      expect(repos).toHaveLength(1);
      expect(repos[0].name).toBe('repo1');
      expect(totalCount).toBe(1);
    });
  });

  describe('getRepo', () => {
    it('should fetch single repo', async () => {
      const { getRepo } = await import('@/lib/github');

      const mockRepo = {
        id: 1,
        name: 'repo1',
        full_name: 'owner/repo1',
        owner: { login: 'owner', avatar_url: 'https://example.com/avatar' },
        private: false,
        html_url: 'https://github.com/owner/repo1',
        description: 'Test',
        fork: false,
        language: 'TypeScript',
        default_branch: 'main',
        stargazers_count: 5,
        forks_count: 1,
        open_issues_count: 0,
        created_at: '2024-01-01T00:00:00Z',
        updated_at: '2024-06-01T00:00:00Z',
        pushed_at: '2024-06-01T00:00:00Z',
      };

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: true,
        json: async () => mockRepo,
      });

      const repo = await getRepo('ghu_token', 'owner', 'repo1');

      expect(repo).not.toBeNull();
      expect(repo?.name).toBe('repo1');
    });

    it('should return null for 404', async () => {
      const { getRepo } = await import('@/lib/github');

      global.fetch = vi.fn().mockResolvedValueOnce({
        ok: false,
        status: 404,
      });

      const repo = await getRepo('ghu_token', 'owner', 'nonexistent');
      expect(repo).toBeNull();
    });
  });
});
