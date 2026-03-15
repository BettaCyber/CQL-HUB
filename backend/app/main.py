from __future__ import annotations

from functools import lru_cache

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware

from .config import Settings
from .github_client import GitHubAPIError, GitHubClient
from .lookup_service import LookupService
from .models import (
    ApiError,
    LookupFileResponse,
    LookupSubmissionRequest,
    QueriesResponse,
    QuerySubmissionRequest,
    SubmissionResponse,
)
from .query_service import QueryService
from .submission_service import SubmissionService


@lru_cache
def get_settings() -> Settings:
    return Settings.from_env()


@lru_cache
def get_github_client() -> GitHubClient:
    return GitHubClient(get_settings())


@lru_cache
def get_query_service() -> QueryService:
    return QueryService(get_github_client(), get_settings())


@lru_cache
def get_lookup_service() -> LookupService:
    return LookupService(get_github_client(), get_settings())


@lru_cache
def get_submission_service() -> SubmissionService:
    return SubmissionService(
        get_github_client(),
        get_query_service(),
        get_lookup_service(),
        get_settings(),
    )


app = FastAPI(title="CQL-HUB API", version="1.0.0")
settings = get_settings()
app.add_middleware(
    CORSMiddleware,
    allow_origins=list(settings.cors_allowed_origins),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/queries", response_model=QueriesResponse, responses={502: {"model": ApiError}})
def list_queries() -> QueriesResponse:
    try:
        return get_query_service().list_queries()
    except GitHubAPIError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


@app.get("/lookup-files", response_model=list[LookupFileResponse], responses={502: {"model": ApiError}})
def list_lookup_files() -> list[LookupFileResponse]:
    try:
        return get_lookup_service().list_lookup_files()
    except GitHubAPIError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


@app.post(
    "/submissions",
    response_model=SubmissionResponse,
    status_code=status.HTTP_201_CREATED,
    responses={422: {"model": ApiError}, 502: {"model": ApiError}, 503: {"model": ApiError}},
)
def submit_query(payload: QuerySubmissionRequest) -> SubmissionResponse:
    try:
        return get_submission_service().submit_query(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except GitHubAPIError as exc:
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE if exc.status_code in {401, 403} else status.HTTP_502_BAD_GATEWAY
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc


@app.post(
    "/lookup-submissions",
    response_model=SubmissionResponse,
    status_code=status.HTTP_201_CREATED,
    responses={422: {"model": ApiError}, 502: {"model": ApiError}, 503: {"model": ApiError}},
)
def submit_lookup(payload: LookupSubmissionRequest) -> SubmissionResponse:
    try:
        return get_submission_service().submit_lookup(payload)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
    except GitHubAPIError as exc:
        status_code = status.HTTP_503_SERVICE_UNAVAILABLE if exc.status_code in {401, 403} else status.HTTP_502_BAD_GATEWAY
        raise HTTPException(status_code=status_code, detail=str(exc)) from exc
