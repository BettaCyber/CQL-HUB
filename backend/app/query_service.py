from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from .config import Settings
from .github_client import GitHubAPIError, GitHubClient
from .models import QueriesResponse, QueryFilePayload, QuerySubmissionRequest


class QueryService:
    def __init__(self, github_client: GitHubClient, settings: Settings) -> None:
        self.github_client = github_client
        self.settings = settings
        self._cache: dict[str, QueryFilePayload] | None = None
        self._cache_expiry = datetime.now(timezone.utc)

    def _cache_valid(self) -> bool:
        return self._cache is not None and datetime.now(timezone.utc) < self._cache_expiry

    def list_queries(self) -> QueriesResponse:
        if self._cache_valid():
            return QueriesResponse(queries=self._cache or {})

        queries: dict[str, QueryFilePayload] = {}
        try:
            query_files = self.github_client.list_files("queries")
            for file_info in query_files:
                filename = file_info["name"]
                if not filename.lower().endswith((".yml", ".yaml")):
                    continue
                path = file_info["path"]
                raw_yaml = self.github_client.get_file_text(path)
                parsed = yaml.safe_load(raw_yaml) or {}
                normalized = self._normalize_query(parsed)
                created_date = self.github_client.get_file_commit_date(path)
                queries[filename] = QueryFilePayload(
                    filename=filename,
                    created_date=created_date,
                    parsed_content=normalized,
                )
        except GitHubAPIError as exc:
            if exc.status_code != 404:
                raise
            queries = self._load_local_queries()

        self._cache = queries
        self._cache_expiry = datetime.now(timezone.utc) + timedelta(seconds=self.settings.cache_ttl_seconds)
        return QueriesResponse(queries=queries)

    def query_exists(self, name: str) -> bool:
        lower_name = name.strip().lower()
        for query in self.list_queries().queries.values():
            parsed_name = str(query.parsed_content.get("name", "")).strip().lower()
            if parsed_name == lower_name:
                return True
        return False

    def filename_exists(self, filename: str) -> bool:
        return filename in self.list_queries().queries

    def build_query_yaml(self, payload: QuerySubmissionRequest) -> str:
        lines: list[str] = [
            "# --- Query Metadata ---",
            "# Human-readable name for the query. Will be displayed as the title.",
            f"name: {self._escape_scalar(payload.name)}",
            "",
        ]

        if payload.mitre_ids:
            lines.extend(
                [
                    "# MITRE ATT&CK technique IDs",
                    "mitre_ids:",
                    *[f"  - {self._escape_scalar(item)}" for item in payload.mitre_ids],
                    "",
                ]
            )

        lines.extend(
            [
                "# Description of what the query does and its purpose.",
                "description: |",
                *[f"  {line}" for line in payload.description.splitlines()],
                "",
                "# The author or team that created the query.",
                f"author: {self._escape_scalar(payload.author)}",
                "",
            ]
        )

        if payload.log_sources:
            lines.extend(
                [
                    "# The required log sources to run this query successfully in Next-Gen SIEM.",
                    "log_sources:",
                    *[f"  - {self._escape_scalar(item)}" for item in payload.log_sources],
                    "",
                ]
            )

        if payload.tags:
            lines.extend(
                [
                    "# Tags for filtering and categorization.",
                    "tags:",
                    *[f"  - {self._escape_scalar(item)}" for item in payload.tags],
                    "",
                ]
            )

        if payload.cs_required_modules:
            lines.extend(
                [
                    "# The CrowdStrike modules required to run this query.",
                    "cs_required_modules:",
                    *[f"  - {self._escape_scalar(item)}" for item in payload.cs_required_modules],
                    "",
                ]
            )

        lines.extend(
            [
                "# --- Query Content ---",
                "# The actual CrowdStrike Query Language (CQL) code.",
                "cql: |",
                *[f"  {line}" for line in payload.cql.splitlines()],
                "",
            ]
        )

        if payload.explanation:
            lines.extend(
                [
                    "# Explanation of the query.",
                    "explanation: |",
                    *[f"  {line}" for line in payload.explanation.splitlines()],
                ]
            )

        return "\n".join(lines).rstrip() + "\n"

    def clear_cache(self) -> None:
        self._cache = None
        self._cache_expiry = datetime.now(timezone.utc)

    def _load_local_queries(self) -> dict[str, QueryFilePayload]:
        queries: dict[str, QueryFilePayload] = {}
        for path in sorted(self.settings.local_queries_dir.glob("*.y*ml")):
            parsed = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            normalized = self._normalize_query(parsed)
            created_date = datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
            queries[path.name] = QueryFilePayload(
                filename=path.name,
                created_date=created_date,
                parsed_content=normalized,
            )
        return queries

    def _normalize_query(self, data: dict[str, Any]) -> dict[str, Any]:
        normalized = dict(data)
        for key in ("tags", "mitre_ids", "log_sources", "cs_required_modules"):
            value = normalized.get(key)
            if value is None:
                normalized[key] = []
        normalized.setdefault("description", "")
        normalized.setdefault("author", self.settings.app_brand_name)
        normalized.setdefault("cql", "")
        normalized.setdefault("explanation", "")
        return normalized

    def _escape_scalar(self, value: str) -> str:
        if not value:
            return '""'
        if any(ch in value for ch in ':#@`|>*&!%{}[],?') or value.strip() != value or value.lower() in {
            "true",
            "false",
            "null",
            "yes",
            "no",
            "on",
            "off",
        }:
            return '"' + value.replace('"', '\\"') + '"'
        return value
