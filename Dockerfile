# ── Build stage: install everything, build the dashboard, generate Prisma client ──
FROM node:22-slim AS build
WORKDIR /app

# Prisma needs openssl
RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY package.json package-lock.json ./
COPY server/package.json server/package.json
COPY client/package.json client/package.json
RUN npm ci

COPY . .
RUN npx prisma generate && npm run build

# ── Runtime stage ────────────────────────────────────────────────────────────────
FROM node:22-slim AS runtime
ENV NODE_ENV=production
WORKDIR /app

RUN apt-get update \
  && apt-get install -y --no-install-recommends openssl ca-certificates \
  && rm -rf /var/lib/apt/lists/*

COPY --from=build --chown=node:node /app /app

USER node

# 8080 = public fake site, 3000 = internal dashboard API + UI
EXPOSE 8080 3000

# Run pending migrations, then start both servers.
CMD ["sh", "-c", "npx prisma migrate deploy && node server/src/index.js"]
