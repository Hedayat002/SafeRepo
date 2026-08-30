import mongoose from 'mongoose';
import { logger } from '@/lib/logger';

/**
 * Mongoose connection singleton.
 *
 * Caches the connection promise to avoid multiple connections
 * in development with Next.js hot module reloading.
 *
 * MongoDB access is server-side only.
 */

interface MongooseCache {
  conn: typeof mongoose | null;
  promise: Promise<typeof mongoose> | null;
}

/* eslint-disable no-var */
declare global {
  var mongooseCache: MongooseCache | undefined;
}
/* eslint-enable no-var */

const cached: MongooseCache = global.mongooseCache ?? { conn: null, promise: null };

if (!global.mongooseCache) {
  global.mongooseCache = cached;
}

export async function connectDB(): Promise<typeof mongoose> {
  if (cached.conn) {
    return cached.conn;
  }

  if (!cached.promise) {
    const uri = process.env.MONGODB_URI;

    if (!uri) {
      throw new Error('MONGODB_URI environment variable is not defined');
    }

    logger.info('Connecting to MongoDB...');

    cached.promise = mongoose.connect(uri, {
      bufferCommands: false,
    }).then((mongooseInstance) => {
      logger.info('MongoDB connected successfully');
      return mongooseInstance;
    });
  }

  try {
    cached.conn = await cached.promise;
  } catch (err) {
    cached.promise = null;
    logger.error({ err }, 'MongoDB connection failed');
    throw err;
  }

  return cached.conn;
}

/**
 * Check if MongoDB is connected.
 * Used by the health check endpoint.
 */
export function isDBConnected(): boolean {
  return mongoose.connection.readyState === 1;
}
