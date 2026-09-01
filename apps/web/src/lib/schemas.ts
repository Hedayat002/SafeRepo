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

/** Request body for POST /api/v1/scans */
export const createScanSchema = z.object({
  repositoryOwner: z
    .string()
    .min(1, 'repositoryOwner is required')
    .max(100, 'repositoryOwner is too long')
    .regex(/^[a-zA-Z0-9._-]+$/, 'Invalid repositoryOwner format'),
  repositoryName: z
    .string()
    .min(1, 'repositoryName is required')
    .max(100, 'repositoryName is too long')
    .regex(/^[a-zA-Z0-9._-]+$/, 'Invalid repositoryName format'),
  branch: z
    .string()
    .min(1)
    .max(100)
    .regex(/^[a-zA-Z0-9._/-]+$/, 'Invalid branch format')
    .optional(),
});

export type CreateScanBody = z.infer<typeof createScanSchema>;

/** Query parameters for GET /api/v1/scans */
export const scansQuerySchema = z.object({
  page: z.coerce.number().int().positive().default(1),
  per_page: z.coerce.number().int().min(1).max(100).default(20),
  status: z
    .enum(['queued', 'cloning', 'scanning', 'normalizing', 'completed', 'failed', 'timed_out'])
    .optional(),
});

export type ScansQuery = z.infer<typeof scansQuerySchema>;

/** Path parameter for GET /api/v1/scans/:id */
export const scanIdParamSchema = z.object({
  id: z
    .string()
    .regex(/^[0-9a-fA-F]{24}$/, 'Invalid scan ID format'),
});

export type ScanIdParam = z.infer<typeof scanIdParamSchema>;
