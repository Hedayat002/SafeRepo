import mongoose, { Schema, type Document, type Model } from 'mongoose';
import type { ScanStatus, ScanSummary } from '@/types';

/**
 * Mongoose Scan model.
 *
 * Stores scan requests and their status.
 * Per DATABASE_DESIGN.md and Phase 02 requirements.
 */

export interface IScan extends Document {
  userId: mongoose.Types.ObjectId;
  repositoryOwner: string;
  repositoryName: string;
  repositoryUrl: string;
  branch: string;
  commitSha: string | null;
  status: ScanStatus;
  scanners: string[];
  summary: ScanSummary;
  error: string | null;
  workspacePath: string | null;
  startedAt: Date | null;
  completedAt: Date | null;
  duration: number | null;
  createdAt: Date;
  updatedAt: Date;
}

const scanSchema = new Schema<IScan>(
  {
    userId: {
      type: Schema.Types.ObjectId,
      required: true,
      ref: 'User',
      index: true,
    },
    repositoryOwner: {
      type: String,
      required: true,
      trim: true,
    },
    repositoryName: {
      type: String,
      required: true,
      trim: true,
    },
    repositoryUrl: {
      type: String,
      required: true,
      trim: true,
    },
    branch: {
      type: String,
      required: true,
      trim: true,
    },
    commitSha: {
      type: String,
      default: null,
    },
    status: {
      type: String,
      required: true,
      enum: ['queued', 'cloning', 'scanning', 'normalizing', 'completed', 'failed', 'timed_out'],
      default: 'queued',
      index: true,
    },
    scanners: {
      type: [String],
      default: ['semgrep', 'trivy', 'gitleaks', 'osv', 'npm-audit', 'pip-audit'],
    },
    summary: {
      total: { type: Number, default: 0 },
      critical: { type: Number, default: 0 },
      high: { type: Number, default: 0 },
      medium: { type: Number, default: 0 },
      low: { type: Number, default: 0 },
      info: { type: Number, default: 0 },
    },
    error: {
      type: String,
      default: null,
    },
    workspacePath: {
      type: String,
      default: null,
    },
    startedAt: {
      type: Date,
      default: null,
    },
    completedAt: {
      type: Date,
      default: null,
    },
    duration: {
      type: Number,
      default: null,
    },
  },
  {
    timestamps: true,
    collection: 'scans',
  }
);

// Indexes per DATABASE_DESIGN.md
scanSchema.index({ repositoryOwner: 1, repositoryName: 1 });
scanSchema.index({ createdAt: -1 });

export const Scan: Model<IScan> =
  mongoose.models.Scan ?? mongoose.model<IScan>('Scan', scanSchema);
