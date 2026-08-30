import { z } from 'zod';

/**
 * Shared Zod validation schemas for SafeRepo API routes.
 * All API inputs are validated with Zod before processing.
 */

/** Query parameters for GET /api/v1/repos */
export const reposQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  per_page: z.coerce.number().int().min(1).max(100).default(30),
});

export type ReposQuery = z.infer<typeof reposQuerySchema>;

/** Path parameters for GET /api/v1/repos/:owner/:name */
export const repoParamsSchema = z.object({
  owner: z.string().min(1, 'Owner is required').max(255),
  name: z.string().min(1, 'Repository name is required').max(255),
});

export type RepoParams = z.infer<typeof repoParamsSchema>;

/** OAuth callback query parameters */
export const oauthCallbackSchema = z.object({
  code: z.string().min(1, 'Authorization code is required'),
  state: z.string().min(1, 'State parameter is required'),
});

export type OAuthCallback = z.infer<typeof oauthCallbackSchema>;
