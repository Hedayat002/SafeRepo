import mongoose, { Schema, type Document, type Model } from 'mongoose';

/**
 * Mongoose Session model.
 *
 * Server-side session storage backed by MongoDB.
 * Per H1 decision: opaque session ID, MongoDB-backed,
 * TTL expiration, revocation support.
 *
 * GitHub access tokens are stored here — server-side only,
 * never sent to the client.
 */

export interface ISession extends Document {
  sessionId: string;
  userId: mongoose.Types.ObjectId;
  githubAccessToken: string;
  expiresAt: Date;
  createdAt: Date;
}

const sessionSchema = new Schema<ISession>(
  {
    sessionId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    userId: {
      type: Schema.Types.ObjectId,
      required: true,
      ref: 'User',
      index: true,
    },
    githubAccessToken: {
      type: String,
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      index: { expires: 0 }, // MongoDB TTL index — auto-deletes expired sessions
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    collection: 'sessions',
  }
);

/**
 * Prevent model recompilation in Next.js HMR.
 */
export const Session: Model<ISession> =
  mongoose.models.Session ?? mongoose.model<ISession>('Session', sessionSchema);
