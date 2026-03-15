from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    github_token: str | None
    github_owner: str
    github_repo: str
    github_base_branch: str
    data_source: str
    cache_ttl_seconds: int
    app_brand_name: str
    app_company_url: str
    cors_allowed_origins: tuple[str, ...]
    local_queries_dir: Path
    local_lookup_dir: Path

    @property
    def repo_html_url(self) -> str:
        return f"https://github.com/{self.github_owner}/{self.github_repo}"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            github_token=os.getenv("GITHUB_TOKEN") or None,
            github_owner=os.getenv("GITHUB_OWNER", "BettaCyber"),
            github_repo=os.getenv("GITHUB_REPO", "CQL-HUB"),
            github_base_branch=os.getenv("GITHUB_BASE_BRANCH", "main"),
            data_source=os.getenv("DATA_SOURCE", "local").strip().lower(),
            cache_ttl_seconds=int(os.getenv("CACHE_TTL_SECONDS", "600")),
            app_brand_name=os.getenv("APP_BRAND_NAME", "Betta_Cyber"),
            app_company_url=os.getenv("APP_COMPANY_URL", "https://betta.gp"),
            cors_allowed_origins=tuple(
                origin.strip()
                for origin in os.getenv("ALLOWED_ORIGINS", "*").split(",")
                if origin.strip()
            ),
            local_queries_dir=Path(os.getenv("LOCAL_QUERIES_DIR", "/app/queries")),
            local_lookup_dir=Path(os.getenv("LOCAL_LOOKUP_DIR", "/app/lookup-files")),
        )
