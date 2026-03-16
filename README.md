# CQL-HUB

Dockerized Betta_Cyber query hub application with:

- a static frontend served by Nginx
- a FastAPI backend
- local packaged query and lookup storage by default for Docker/on-prem
- optional GitHub-backed query and lookup storage when explicitly enabled
- PR-based submission flow for new queries and lookup files

## Structure

- `frontend/`: static web application
- `backend/`: FastAPI API
- `queries/`: published query files
- `lookup-files/`: published lookup files and manifest
- `docs/`: deployment documentation

## Local Docker

1. Copy `.env.example` to `.env`
2. Set `GITHUB_TOKEN` with `contents:write`, `pull_requests:write`, `metadata:read`
3. Run:

```powershell
docker compose up --build
```

Frontend:

- `http://localhost:8080`

Backend:

- `http://localhost:8002`

Important local env values:

- `DATA_SOURCE=local`
- `SYNC_FROM_GITHUB=true`
- `SYNC_INTERVAL_SECONDS=3600`
- `API_BASE_URL=/api`
- `API_PROXY_TARGET=http://backend:8002`
- `ALLOWED_ORIGINS=*`
- `CACHE_TTL_SECONDS=600`

For on-prem Docker, the backend now reads from the bundled local `queries/` and `lookup-files/` directories by default. This avoids slow GitHub round-trips and makes first-load behavior faster and more stable.

The Dockerized frontend now proxies `/api/*` through Nginx to the backend container. That means the browser no longer needs to call `localhost:8002` directly, which avoids remote-host deployment failures where the browser would otherwise try to reach its own local machine.

If you want newly approved GitHub queries and lookup files to appear automatically without rebuilding the backend image, enable the background sync:

- `SYNC_FROM_GITHUB=true`
- `SYNC_INTERVAL_SECONDS=3600`

With that enabled, the backend keeps serving fast local files but refreshes them from GitHub on the configured interval and clears its cache after each sync.

## AWS Amplify frontend

Amplify can host the frontend only. It cannot use `localhost:8002` in production, so the backend must be deployed separately and exposed on a public HTTPS URL.

Required Amplify environment variables:

- `API_BASE_URL=https://your-backend-domain`
- `GITHUB_REPO_URL=https://github.com/BettaCyber/CQL-HUB`
- `COMPANY_URL=https://betta.gp`

This repo includes [amplify.yml](./amplify.yml), which publishes `frontend/` as the site root and generates `config.js` during the Amplify build.

Required backend environment variables for hosted deployments:

- `GITHUB_TOKEN`
- `GITHUB_OWNER=BettaCyber`
- `GITHUB_REPO=CQL-HUB`
- `GITHUB_BASE_BRANCH=main`
- `ALLOWED_ORIGINS=https://your-amplify-domain`

## Deployment docs

See [docs/deployment.md](./docs/deployment.md) for local Docker, Amplify frontend setup, backend hosting requirements, and CORS/runtime config details.

## GitHub repository

The application expects this repository to be hosted at:

- `https://github.com/BettaCyber/CQL-HUB`

The backend reads published data from:

- `queries/`
- `lookup-files/`

New submissions are written to feature branches and opened as pull requests into `main`.
