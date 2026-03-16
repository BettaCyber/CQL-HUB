# Deployment Guide

## Deployment Modes

This project supports:

- local Docker with frontend on `localhost:8080` and backend on `localhost:8002`
- hosted frontend with a separately hosted backend

## On-Prem Default Behavior

For Docker/on-prem deployments, the backend should use local packaged data instead of calling GitHub for every page load.

Recommended values:

- `DATA_SOURCE=local`
- `SYNC_FROM_GITHUB=true`
- `SYNC_INTERVAL_SECONDS=3600`
- `CACHE_TTL_SECONDS=600`

This avoids intermittent empty states caused by upstream GitHub latency or failures and makes refresh behavior much faster.

If `SYNC_FROM_GITHUB=true`, the backend still serves the local packaged files first, but it also refreshes `queries/` and `lookup-files/` from GitHub on a background interval. This is the recommended on-prem mode when you want newly approved GitHub content to show up automatically without rebuilding containers.

## Why Amplify Failed

Amplify deployed only the static frontend. The browser then tried to reach `http://localhost:8002`, which only works on the local machine. In a hosted deployment, the frontend must call a real public backend URL.

## Frontend Variables

Set these in Amplify:

- `API_BASE_URL=https://your-backend-domain`
- `GITHUB_REPO_URL=https://github.com/BettaCyber/CQL-HUB`
- `COMPANY_URL=https://betta.gp`

If `API_BASE_URL` is not provided:

- local hosts default to `http://localhost:8002`
- non-local hosts default to `${window.location.origin}/api`

`amplify.yml` writes the runtime `config.js` during the Amplify build and publishes `frontend/` as the site root.

## Backend Variables

Set these where the FastAPI backend runs:

- `GITHUB_TOKEN`
- `GITHUB_OWNER=BettaCyber`
- `GITHUB_REPO=CQL-HUB`
- `GITHUB_BASE_BRANCH=main`
- `CACHE_TTL_SECONDS=60`
- `ALLOWED_ORIGINS=https://your-amplify-domain`

Use comma-separated values in `ALLOWED_ORIGINS` when more than one frontend origin is allowed.

## Local Docker

Example `.env`:

```env
DATA_SOURCE=local
SYNC_FROM_GITHUB=true
SYNC_INTERVAL_SECONDS=3600
API_PORT=8002
FRONTEND_PORT=8080
API_BASE_URL=/api
API_PROXY_TARGET=http://backend:8002
CACHE_TTL_SECONDS=600
ALLOWED_ORIGINS=*
```

Run:

```powershell
docker compose up --build
```

In the Docker deployment, the frontend container now proxies `/api/*` to the backend container through Nginx. This is the recommended remote-host setup because the browser talks to the same frontend origin instead of trying to connect to `localhost:8002`.

## Backend Hosting for Amplify Frontends

Amplify Hosting does not run this FastAPI backend. Deploy the backend separately on a public HTTPS endpoint such as:

- AWS App Runner
- Amazon ECS with an ALB
- EC2 behind Nginx or ALB

Then point Amplify `API_BASE_URL` at that backend URL.
