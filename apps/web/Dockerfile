# syntax=docker/dockerfile:1
# Multi-stage Dockerfile for SafeRepo Web Application (Next.js 16.3.3 Standalone)
# Security boundaries:
# - Runs as unprivileged non-root user (nextjs:nodejs, UID 1001)
# - Zero Docker socket access or Docker CLI binaries
# - Read-only application code with isolated runtime state

# Stage 1: Base Alpine runtime
FROM node:24.19.0-alpine AS base
WORKDIR /app
RUN apk add --no-cache libc6-compat

# Stage 2: Install dependencies (monorepo root context)
FROM base AS deps
WORKDIR /app
COPY package.json package-lock.json ./
COPY apps/web/package.json ./apps/web/
RUN npm ci

# Stage 3: Build Next.js application in standalone mode
FROM base AS builder
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY package.json package-lock.json ./
COPY apps/web ./apps/web

# Ensure public directory exists for static copy in runner
RUN mkdir -p /app/apps/web/public

ENV NEXT_TELEMETRY_DISABLED=1
ENV NODE_ENV=production

WORKDIR /app/apps/web
# Run build with non-secret build-time placeholders for static analysis
RUN MONGODB_URI="mongodb://localhost:27017/saferepo" \
    GITHUB_APP_ID="build-placeholder-app-id" \
    GITHUB_CLIENT_ID="build-placeholder-client-id" \
    GITHUB_CLIENT_SECRET="build-placeholder-client-secret" \
    SESSION_SECRET="build-placeholder-session-secret-32-chars-long" \
    NEXT_PUBLIC_APP_URL="http://localhost" \
    ALLOWED_ORIGINS="http://localhost" \
    npm run build

# Stage 4: Minimal production runner
FROM base AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV NEXT_TELEMETRY_DISABLED=1
ENV PORT=3000
ENV HOSTNAME="0.0.0.0"

# Security: Create non-root system user and group
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 nextjs

# Copy standalone build artifacts from builder
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/public ./apps/web/public
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/standalone ./
COPY --from=builder --chown=nextjs:nodejs /app/apps/web/.next/static ./apps/web/.next/static

# Set permissions for nextjs user
USER nextjs

EXPOSE 3000

CMD ["node", "apps/web/server.js"]
