# syntax=docker/dockerfile:1
# CRISP 2.0 - Production Multi-Stage Container Image
# Combines Node.js 20 LTS runtime with Python 3 for the Multi-Agent & Risk Engines

# Stage 1: Build Frontend Assets
FROM node:20-slim AS frontend-builder
WORKDIR /app
COPY package*.json ./
RUN npm ci --prefer-offline --no-audit
COPY . .
RUN npm run build

# Stage 2: Production Runtime
FROM node:20-slim AS runner

# Install Python 3 and SQLite runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    sqlite3 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Set production environment flags
ENV NODE_ENV=production \
    PORT=3000 \
    PYTHONUNBUFFERED=1

# Copy package manifests and production dependencies
COPY package*.json ./
RUN npm ci --omit=dev --prefer-offline --no-audit

# Copy built frontend bundle from Stage 1
COPY --from=frontend-builder /app/dist ./dist

# Copy backend server, python services, scripts, and initial data
COPY server.ts tsconfig.json ./
COPY services ./services
COPY scripts ./scripts
COPY data ./data
COPY src/data ./src/data

# Ensure data directories exist and have proper permissions
RUN mkdir -p data/backups data/chroma_db logs

# Expose HTTP port
EXPOSE 3000

# Health check probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/api/health || exit 1

# Run database migration check and start production server
CMD ["sh", "-c", "python3 scripts/migrate.py && npx tsx server.ts"]
