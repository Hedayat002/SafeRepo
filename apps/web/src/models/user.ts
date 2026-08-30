import mongoose, { Schema, type Document, type Model } from 'mongoose';

/**
 * Mongoose User model.
 *
 * Stores authenticated users via GitHub App OAuth.
 * Per DATABASE_DESIGN.md specifications.
 */

export interface IUser extends Document {
  githubId: string;
  username: string;
  displayName: string | null;
  email: string | null;
  avatarUrl: string | null;
  createdAt: Date;
  updatedAt: Date;
}

const userSchema = new Schema<IUser>(
  {
    githubId: {
      type: String,
      required: true,
      unique: true,
      index: true,
    },
    username: {
      type: String,
      required: true,
    },
    displayName: {
      type: String,
      default: null,
    },
    email: {
      type: String,
      default: null,
    },
    avatarUrl: {
      type: String,
      default: null,
    },
  },
  {
    timestamps: true,
    collection: 'users',
  }
);

/**
 * Prevent model recompilation in Next.js HMR.
 */
export const User: Model<IUser> =
  mongoose.models.User ?? mongoose.model<IUser>('User', userSchema);
