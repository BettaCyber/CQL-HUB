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

## Local run

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

## GitHub repository

The application expects this repository to be hosted at:

- `https://github.com/Betta_Cyber/CQL-HUB`

The backend reads published data from:

- `queries/`
- `lookup-files/`

New submissions are written to feature branches and opened as pull requests into `main`.
