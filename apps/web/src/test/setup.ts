import { MongoMemoryServer } from 'mongodb-memory-server';
import mongoose from 'mongoose';
import { beforeAll, afterAll, afterEach } from 'vitest';

/**
 * Global test setup for Vitest.
 *
 * - Sets test environment variables (placeholders only)
 * - Starts MongoMemoryServer (or uses local MongoDB if running) for isolation
 * - Cleans up collections after each test
 * - Tears down gracefully after all tests
 */

let mongoServer: MongoMemoryServer | null = null;

beforeAll(async () => {
  // Set test environment
  (process.env as Record<string, string | undefined>).NODE_ENV = 'test';
  process.env.GITHUB_APP_ID = 'test-app-id';
  process.env.GITHUB_CLIENT_ID = 'test-client-id';
  process.env.GITHUB_CLIENT_SECRET = 'test-client-secret';
  process.env.SESSION_SECRET = 'test-session-secret-that-is-at-least-32-characters-long';
  process.env.NEXT_PUBLIC_APP_URL = 'http://localhost:3000';
  process.env.ALLOWED_ORIGINS = 'http://localhost:3000';

  if (mongoose.connection.readyState !== 1) {
    // Primary: use Docker MongoDB (always available via docker-compose)
    const dockerUri = 'mongodb://admin:password@localhost:27017/saferepo_test?authSource=admin';
    try {
      process.env.MONGODB_URI = dockerUri;
      await mongoose.connect(dockerUri, { serverSelectionTimeoutMS: 2000 });
    } catch {
      // Fallback: MongoMemoryServer for CI or environments without Docker
      mongoServer = await MongoMemoryServer.create();
      const memUri = mongoServer.getUri();
      process.env.MONGODB_URI = memUri;
      await mongoose.connect(memUri);
    }
  }
});

afterEach(async () => {
  if (mongoose.connection.readyState === 1) {
    const collections = mongoose.connection.collections;
    for (const key in collections) {
      await collections[key].deleteMany({});
    }
  }
});

afterAll(async () => {
  if (mongoose.connection.readyState !== 0) {
    await mongoose.disconnect();
  }
  if (mongoServer) {
    await mongoServer.stop();
  }
});
