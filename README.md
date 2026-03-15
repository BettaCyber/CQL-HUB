# CQL-HUB

Dockerized Betta_Cyber query hub application with:

- a static frontend served by Nginx
- a FastAPI backend
- GitHub-backed query and lookup storage in this repository
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

- `API_BASE_URL=http://localhost:8002`
- `ALLOWED_ORIGINS=*`

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
