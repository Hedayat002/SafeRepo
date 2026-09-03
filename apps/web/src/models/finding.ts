import mongoose, { Schema, type Document, type Model } from 'mongoose';
import type { FindingCategory, FindingScanner, FindingSeverity } from '@/types';

/**
 * Mongoose Finding model.
 *
 * Stores normalized security findings from all scanners.
 * Implements DATABASE_DESIGN.md and Phase 03 requirements.
 */

export interface IFinding extends Document {
  scanId: mongoose.Types.ObjectId;
  userId: mongoose.Types.ObjectId;
  scanner: FindingScanner;
  category: FindingCategory;
  severity: FindingSeverity;
  title: string;
  description: string;
  file: string;
  line: number;
  endLine?: number;
  column?: number;
  endColumn?: number;
  codeSnippet?: string;
  package?: string;
  packageVersion?: string;
  fixedVersion?: string;
  vulnerabilityId: string;
  remediation?: string;
  fingerprint: string;
  metadata?: Record<string, unknown>;
  createdAt: Date;
  updatedAt: Date;
}

const findingSchema = new Schema<IFinding>(
  {
    scanId: {
      type: Schema.Types.ObjectId,
      required: true,
      ref: 'Scan',
      index: true,
    },
    userId: {
      type: Schema.Types.ObjectId,
      required: true,
      ref: 'User',
      index: true,
    },
    scanner: {
      type: String,
      required: true,
      enum: ['semgrep', 'trivy', 'gitleaks', 'osv', 'npm-audit', 'pip-audit'],
    },
    category: {
      type: String,
      required: true,
      enum: ['sast', 'dependency', 'secret', 'configuration', 'license'],
    },
    severity: {
      type: String,
      required: true,
      enum: ['critical', 'high', 'medium', 'low', 'info'],
    },
    title: {
      type: String,
      required: true,
      trim: true,
    },
    description: {
      type: String,
      default: '',
      trim: true,
    },
    file: {
      type: String,
      default: '',
      trim: true,
    },
    line: {
      type: Number,
      default: 0,
    },
    endLine: {
      type: Number,
    },
    column: {
      type: Number,
    },
    endColumn: {
      type: Number,
    },
    codeSnippet: {
      type: String,
      trim: true,
    },
    package: {
      type: String,
      trim: true,
    },
    packageVersion: {
      type: String,
      trim: true,
    },
    fixedVersion: {
      type: String,
      trim: true,
    },
    vulnerabilityId: {
      type: String,
      default: '',
      trim: true,
    },
    remediation: {
      type: String,
      trim: true,
    },
    fingerprint: {
      type: String,
      required: true,
      trim: true,
    },
    metadata: {
      type: Schema.Types.Mixed,
      default: () => ({}),
    },
  },
  {
    timestamps: true,
    collection: 'findings',
  }
);

// Indexes per DATABASE_DESIGN.md
findingSchema.index({ scanId: 1, severity: 1 });
findingSchema.index({ scanId: 1, category: 1 });
findingSchema.index({ scanId: 1, scanner: 1 });
findingSchema.index({ scanId: 1, fingerprint: 1 }, { unique: true });
findingSchema.index({ createdAt: -1 });

export const Finding: Model<IFinding> =
  mongoose.models.Finding ?? mongoose.model<IFinding>('Finding', findingSchema);
