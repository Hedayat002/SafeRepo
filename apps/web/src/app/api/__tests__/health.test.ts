import { describe, it, expect } from 'vitest';
import { GET as healthHandler } from '@/app/api/health/route';

describe('GET /api/health', () => {
  it('should return 200 and status ok when DB is connected', async () => {
    const response = await healthHandler();
    expect(response.status).toBe(200);

    const json = await response.json();
    expect(json.status).toBe('ok');
    expect(json.db).toBe('connected');
    expect(json.timestamp).toBeDefined();
  });
});
