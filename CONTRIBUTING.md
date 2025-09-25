# Contributing to AuditGH

Thank you for contributing! This guide helps you get a working dev environment and contribute high‑quality changes safely.

## Prerequisites

- Docker Desktop with Docker Compose v2 (use `docker compose`, not `docker-compose`)
- Node.js 18+ (for web development)
- Python 3.11+ (for scripts)
- GitHub Personal Access Token with `repo` and `read:org`

## Repository Layout

- `server/` — Backend API (Node/TypeScript) exposed at `http://localhost:8080`
- `web/` — Frontend (React + Vite + TypeScript)
- `db/portal_init/` — PostgreSQL schema and functions (applied via Postgres init)
- `docker-compose.portal.yml` — Full portal stack (db, postgrest, server, web)
- `docker-compose.dev.yml` — Dev stack with hot‑reload for `web/`
- `setup.sh` — Dev‑only full reset and one‑time seeding (destroys DB volume)
- `bootstrap.sh` — First‑time setup (creates `.env`, brings stack up)

## First‑Time Setup

1) Create `.env`

```bash
cp .env.sample .env
# Edit .env and set at least:
#   GITHUB_ORG=your-org
#   GITHUB_TOKEN=ghp_xxx
```

2) Bring the portal stack up

```bash
./bootstrap.sh
# Web: http://localhost:5173
# PostgREST: http://localhost:3001
# Server: http://localhost:8080
```

3) Prepare local bind directories (safe to re‑run)

```bash
./prepare_bind_dirs.sh
```

## Dev Workflow Options

### A) Run Dev Stack with Hot‑Reload (recommended for UI work)

```bash
# Start dev stack (web dev server on http://localhost:3000)
docker compose -f docker-compose.dev.yml up -d
```

- Web (Vite dev): http://localhost:3000
- Server: http://localhost:8080
- PostgREST: http://localhost:3001

To stop:
```bash
docker compose -f docker-compose.dev.yml down
```

### B) Run Full Portal (prod‑like)

```bash
docker compose -p portal -f docker-compose.portal.yml up -d --build
# Web served by Nginx: http://localhost:5173
```

## Web Development (`web/`)

Install deps and start dev server:
```bash
cd web
npm ci
npm run dev
```

Build locally:
```bash
npm run build
```

Environment variable for API base:
- `VITE_API_BASE` defaults to `http://localhost:8080`

## Git Hooks (Husky)

This repo uses Husky pre‑commit to prevent broken builds and type errors.

Install hooks once (top‑level Git hooks, Husky installed from `web/`):
```bash
npm --prefix web ci
npm --prefix web run prepare
```

What the pre‑commit does:
- Runs TypeScript type‑check: `npm --prefix web run typecheck`
- Ensures the web build succeeds: `npm --prefix web run build`

If you need to skip hooks temporarily:
```bash
git commit -m "your message" --no-verify
```

## Seeding and Periodic Refresh

- Dev‑only full reset + seed (WARNING: destroys DB volume):
```bash
./setup.sh
```

- Periodic seeders (optional):
```bash
# Start project discovery/commits refresher (hourly by default)
docker compose -p portal -f docker-compose.portal.yml --profile seed up -d seeder

# Start languages/LOC + OSS bytes refresher (daily by default)
docker compose -p portal -f docker-compose.portal.yml --profile seed up -d seeder_langloc
```

Configure cadence in `.env`:
- `SEED_INTERVAL=3600`
- `SEED_LANGLOC_INTERVAL=86400`

## CI/CD (suggested)

Add a GitHub Actions workflow to validate web builds on every push/PR:
```yaml
name: CI
on: [push, pull_request]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
          cache: 'npm'
          cache-dependency-path: web/package-lock.json
      - name: Install & Build (web)
        working-directory: web
        run: |
          npm ci
          npm run build
```

## Troubleshooting

- Docker Compose v2
  - Ensure v2 is available: `docker compose version`
- PostgREST not ready
  - `docker compose -p portal -f docker-compose.portal.yml logs -f postgrest`
- Web build fails (missing files)
  - Ensure `web/src/**` files exist (e.g., `lib/xhr.ts`, `auth.ts`, `components/DataTable.tsx`)
  - Run `npm --prefix web ci && npm --prefix web run build`

## Coding Standards

- Prefer simple solutions and avoid one‑off scripts
- Keep functions/classes focused (SRP) with descriptive names
- Avoid deep nesting; use early returns
- Replace hardcoded values with constants/config
- Add logs at each process step to aid troubleshooting
