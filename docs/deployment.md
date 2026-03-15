# Deployment Guide

## Deployment Modes

This project supports:

- local Docker with frontend on `localhost:8080` and backend on `localhost:8002`
- hosted frontend with a separately hosted backend

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
API_PORT=8002
FRONTEND_PORT=8080
API_BASE_URL=http://localhost:8002
ALLOWED_ORIGINS=*
```

Run:

```powershell
docker compose up --build
```

## Backend Hosting for Amplify Frontends

Amplify Hosting does not run this FastAPI backend. Deploy the backend separately on a public HTTPS endpoint such as:

- AWS App Runner
- Amazon ECS with an ALB
- EC2 behind Nginx or ALB

Then point Amplify `API_BASE_URL` at that backend URL.
