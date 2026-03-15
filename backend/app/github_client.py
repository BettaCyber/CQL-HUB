from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any

import httpx

from .config import Settings


class GitHubAPIError(RuntimeError):
    def __init__(self, message: str, status_code: int = 500) -> None:
        super().__init__(message)
        self.status_code = status_code


class GitHubClient:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.base_url = f"https://api.github.com/repos/{settings.github_owner}/{settings.github_repo}"
        self.headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "cql-hub-backend",
        }
        if settings.github_token:
            self.headers["Authorization"] = f"Bearer {settings.github_token}"

    def _request(self, method: str, path: str, **kwargs: Any) -> Any:
        url = f"{self.base_url}{path}"
        headers = {**self.headers, **kwargs.pop("headers", {})}
        response = httpx.request(method, url, headers=headers, timeout=60, **kwargs)
        if response.status_code >= 400:
            detail = ""
            try:
                payload = response.json()
                detail = payload.get("message", "")
            except Exception:
                detail = response.text
            raise GitHubAPIError(
                f"GitHub API error ({response.status_code}): {detail or 'request failed'}",
                status_code=response.status_code,
            )
        if response.headers.get("content-type", "").startswith("application/json"):
            return response.json()
        return response.text

    def list_files(self, path: str) -> list[dict[str, Any]]:
        data = self._request("GET", f"/contents/{path}")
        if not isinstance(data, list):
            raise GitHubAPIError(f"Unexpected GitHub response for {path}.")
        return data

    def get_file_metadata(self, path: str, ref: str | None = None) -> dict[str, Any]:
        params = {"ref": ref} if ref else None
        return self._request("GET", f"/contents/{path}", params=params)

    def get_file_text(self, path: str, ref: str | None = None) -> str:
        metadata = self.get_file_metadata(path, ref=ref)
        encoded = metadata.get("content", "")
        if not encoded:
            download_url = metadata.get("download_url")
            if not download_url:
                raise GitHubAPIError(f"Unable to fetch content for {path}.")
            response = httpx.get(download_url, timeout=60)
            response.raise_for_status()
            return response.text
        return base64.b64decode(encoded).decode("utf-8")

    def get_file_commit_date(self, path: str) -> str | None:
        commits = self._request("GET", "/commits", params={"path": path, "per_page": 1})
        if isinstance(commits, list) and commits:
            return commits[0]["commit"]["committer"]["date"]
        return None

    def create_branch(self, name: str, base_branch: str) -> None:
        ref_data = self._request("GET", f"/git/ref/heads/{base_branch}")
        sha = ref_data["object"]["sha"]
        self._request(
            "POST",
            "/git/refs",
            json={"ref": f"refs/heads/{name}", "sha": sha},
        )

    def upsert_file(self, path: str, content: bytes, branch: str, message: str) -> None:
        sha = None
        try:
            metadata = self.get_file_metadata(path, ref=branch)
            sha = metadata.get("sha")
        except GitHubAPIError as exc:
            if exc.status_code != 404:
                raise

        payload: dict[str, Any] = {
            "message": message,
            "content": base64.b64encode(content).decode("ascii"),
            "branch": branch,
        }
        if sha:
            payload["sha"] = sha
        self._request("PUT", f"/contents/{path}", json=payload)

    def commit_files(self, branch: str, files: list[tuple[str, bytes]], message_prefix: str) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        for path, content in files:
            message = f"{message_prefix}: {path} ({timestamp})"
            self.upsert_file(path, content, branch=branch, message=message)

    def create_pull_request(self, title: str, body: str, head: str, base: str) -> dict[str, Any]:
        return self._request(
            "POST",
            "/pulls",
            json={"title": title, "body": body, "head": head, "base": base},
        )
