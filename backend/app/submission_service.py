from __future__ import annotations

from datetime import datetime, timezone

from .config import Settings
from .github_client import GitHubClient
from .lookup_service import LookupService
from .models import LookupSubmissionRequest, QuerySubmissionRequest, SubmissionResponse
from .query_service import QueryService
from .validation import (
    build_query_filename,
    sanitize_lookup_filename,
    validate_lookup_content,
    validate_query_payload,
)


class SubmissionService:
    def __init__(
        self,
        github_client: GitHubClient,
        query_service: QueryService,
        lookup_service: LookupService,
        settings: Settings,
    ) -> None:
        self.github_client = github_client
        self.query_service = query_service
        self.lookup_service = lookup_service
        self.settings = settings

    def submit_query(self, payload: QuerySubmissionRequest) -> SubmissionResponse:
        validate_query_payload(payload.cql)
        filename = build_query_filename(payload.name)

        if self.query_service.query_exists(payload.name):
            raise ValueError(f'A query with the name "{payload.name}" already exists.')
        if self.query_service.filename_exists(filename):
            raise ValueError(f'A query file named "{filename}" already exists.')

        branch = self._build_branch_name("query", payload.name)
        self.github_client.create_branch(branch, self.settings.github_base_branch)
        content = self.query_service.build_query_yaml(payload).encode("utf-8")
        self.github_client.commit_files(
            branch=branch,
            files=[(f"queries/{filename}", content)],
            message_prefix=f"Add query submission {payload.name}",
        )
        pr = self.github_client.create_pull_request(
            title=f"Add query: {payload.name}",
            body=(
                "Submitted from the CQL-HUB application for approval.\n\n"
                f"- Query name: {payload.name}\n"
                f"- Author: {payload.author}\n"
            ),
            head=branch,
            base=self.settings.github_base_branch,
        )
        self.query_service.clear_cache()
        return SubmissionResponse(pull_request_url=pr["html_url"], branch=branch)

    def submit_lookup(self, payload: LookupSubmissionRequest) -> SubmissionResponse:
        filename = sanitize_lookup_filename(payload.filename)
        validate_lookup_content(payload.csv_content)

        if self.lookup_service.lookup_exists(filename):
            raise ValueError(f'A lookup file with the filename "{filename}" already exists.')

        branch = self._build_branch_name("lookup", filename.rsplit(".", 1)[0])
        self.github_client.create_branch(branch, self.settings.github_base_branch)
        manifest_text = self.lookup_service.build_manifest_text(
            filename=filename,
            description=payload.description,
            author=payload.author,
        ).encode("utf-8")

        self.github_client.commit_files(
            branch=branch,
            files=[
                (f"lookup-files/{filename}", payload.csv_content.encode("utf-8")),
                ("lookup-files/manifest.json", manifest_text),
            ],
            message_prefix=f"Add lookup submission {filename}",
        )
        pr = self.github_client.create_pull_request(
            title=f"Add lookup file: {filename}",
            body=(
                "Submitted from the CQL-HUB application for approval.\n\n"
                f"- Lookup file: {filename}\n"
                f"- Author: {payload.author}\n"
            ),
            head=branch,
            base=self.settings.github_base_branch,
        )
        self.lookup_service.clear_cache()
        return SubmissionResponse(pull_request_url=pr["html_url"], branch=branch)

    def _build_branch_name(self, prefix: str, value: str) -> str:
        slug = "".join(ch.lower() if ch.isalnum() else "-" for ch in value).strip("-")
        slug = "-".join(segment for segment in slug.split("-") if segment) or prefix
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        return f"submission/{prefix}/{slug[:40]}-{timestamp}"
