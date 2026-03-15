from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path

from .github_client import GitHubClient
from .lookup_service import LookupService
from .query_service import QueryService


class GitHubSyncService:
    def __init__(
        self,
        github_client: GitHubClient,
        query_service: QueryService,
        lookup_service: LookupService,
    ) -> None:
        self.github_client = github_client
        self.query_service = query_service
        self.lookup_service = lookup_service
        self._task: asyncio.Task[None] | None = None

    def start(self, interval_seconds: int) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run(interval_seconds))

    async def stop(self) -> None:
        if self._task is None:
            return
        self._task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._task
        self._task = None

    async def _run(self, interval_seconds: int) -> None:
        while True:
            try:
                await asyncio.to_thread(self.sync_now)
            except Exception as exc:
                print(f"GitHub sync failed: {exc}")
            await asyncio.sleep(interval_seconds)

    def sync_now(self) -> None:
        self._sync_queries()
        self._sync_lookup_files()
        self.query_service.clear_cache()
        self.lookup_service.clear_cache()

    def _sync_queries(self) -> None:
        destination = self.query_service.settings.local_queries_dir
        remote_files = self.github_client.list_files("queries")
        expected_filenames: set[str] = set()

        for file_info in remote_files:
            filename = file_info["name"]
            if not filename.lower().endswith((".yml", ".yaml")):
                continue
            expected_filenames.add(filename)
            content = self.github_client.get_file_text(file_info["path"])
            self._write_text_file(destination / filename, content)

        self._remove_stale_files(destination, expected_filenames, ("*.yml", "*.yaml"))

    def _sync_lookup_files(self) -> None:
        destination = self.lookup_service.settings.local_lookup_dir
        remote_files = self.github_client.list_files("lookup-files")
        expected_filenames: set[str] = {"manifest.json"}

        for file_info in remote_files:
            filename = file_info["name"]
            if filename != "manifest.json" and not filename.lower().endswith(".csv"):
                continue
            expected_filenames.add(filename)
            content = self.github_client.get_file_text(file_info["path"])
            self._write_text_file(destination / filename, content)

        self._remove_stale_files(destination, expected_filenames, ("*.csv", "manifest.json"))

    def _write_text_file(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _remove_stale_files(self, directory: Path, keep_names: set[str], patterns: tuple[str, ...]) -> None:
        directory.mkdir(parents=True, exist_ok=True)
        for pattern in patterns:
            for path in directory.glob(pattern):
                if path.name not in keep_names and path.is_file():
                    path.unlink()
