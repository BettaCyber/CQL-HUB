from __future__ import annotations

import csv
import io
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from .config import Settings
from .github_client import GitHubAPIError, GitHubClient
from .models import LookupFileResponse


class LookupService:
    def __init__(self, github_client: GitHubClient, settings: Settings) -> None:
        self.github_client = github_client
        self.settings = settings
        self._cache: list[LookupFileResponse] | None = None
        self._cache_expiry = datetime.now(timezone.utc)

    def _cache_valid(self) -> bool:
        return self._cache is not None and datetime.now(timezone.utc) < self._cache_expiry

    def list_lookup_files(self) -> list[LookupFileResponse]:
        if self._cache_valid():
            return self._cache or []

        if self._should_use_local_data():
            lookups = self._load_local_lookup_files()
        else:
            try:
                manifest = self._load_manifest()
                manifest_map = {
                    item["name"]: item for item in manifest if isinstance(item, dict) and item.get("name")
                }
                files = self.github_client.list_files("lookup-files")
                lookups: list[LookupFileResponse] = []

                for file_info in files:
                    filename = file_info["name"]
                    if filename == "manifest.json" or not filename.lower().endswith(".csv"):
                        continue

                    csv_text = self.github_client.get_file_text(file_info["path"])
                    columns, row_count, preview_rows = self._parse_csv(csv_text)
                    metadata = manifest_map.get(filename, {})
                    lookups.append(
                        LookupFileResponse(
                            name=filename,
                            description=metadata.get("description", f"Lookup file {filename}"),
                            author=metadata.get("author", self.settings.app_brand_name),
                            columns=columns,
                            row_count=row_count,
                            preview_rows=preview_rows,
                        )
                    )
            except GitHubAPIError as exc:
                if exc.status_code != 404:
                    raise
                lookups = self._load_local_lookup_files()

        lookups.sort(key=lambda item: item.name.lower())
        self._cache = lookups
        self._cache_expiry = datetime.now(timezone.utc) + timedelta(seconds=self.settings.cache_ttl_seconds)
        return lookups

    def lookup_exists(self, filename: str) -> bool:
        lower_name = filename.strip().lower()
        return any(item.name.lower() == lower_name for item in self.list_lookup_files())

    def clear_cache(self) -> None:
        self._cache = None
        self._cache_expiry = datetime.now(timezone.utc)

    def _should_use_local_data(self) -> bool:
        source = self.settings.data_source
        if source == "local":
            return True
        if source == "github":
            return False
        return self.settings.local_lookup_dir.exists() and any(self.settings.local_lookup_dir.glob("*.csv"))

    def load_manifest_text(self) -> str:
        return self.github_client.get_file_text("lookup-files/manifest.json")

    def build_manifest_text(self, filename: str, description: str, author: str) -> str:
        manifest = self._load_manifest()
        filtered = [item for item in manifest if item.get("name", "").lower() != filename.lower()]
        filtered.append({"name": filename, "description": description, "author": author})
        filtered.sort(key=lambda item: item["name"].lower())
        return json.dumps(filtered, indent=2) + "\n"

    def _load_manifest(self) -> list[dict[str, Any]]:
        try:
            manifest_text = self.load_manifest_text()
        except Exception:
            return []
        try:
            parsed = json.loads(manifest_text)
        except json.JSONDecodeError:
            return []
        return parsed if isinstance(parsed, list) else []

    def _parse_csv(self, csv_text: str) -> tuple[list[str], int, list[list[str]]]:
        reader = csv.reader(io.StringIO(csv_text))
        rows = list(reader)
        if not rows:
            return [], 0, []
        columns = rows[0]
        data_rows = rows[1:]
        preview_rows = data_rows[:5]
        return columns, len(data_rows), preview_rows

    def _load_local_lookup_files(self) -> list[LookupFileResponse]:
        manifest_path = self.settings.local_lookup_dir / "manifest.json"
        manifest_map: dict[str, dict[str, Any]] = {}
        if manifest_path.exists():
            try:
                manifest_data = json.loads(manifest_path.read_text(encoding="utf-8"))
                manifest_map = {
                    item["name"]: item for item in manifest_data if isinstance(item, dict) and item.get("name")
                }
            except json.JSONDecodeError:
                manifest_map = {}

        lookups: list[LookupFileResponse] = []
        for path in sorted(self.settings.local_lookup_dir.glob("*.csv")):
            csv_text = path.read_text(encoding="utf-8")
            columns, row_count, preview_rows = self._parse_csv(csv_text)
            metadata = manifest_map.get(path.name, {})
            lookups.append(
                LookupFileResponse(
                    name=path.name,
                    description=metadata.get("description", f"Lookup file {path.name}"),
                    author=metadata.get("author", self.settings.app_brand_name),
                    columns=columns,
                    row_count=row_count,
                    preview_rows=preview_rows,
                )
            )
        return lookups
