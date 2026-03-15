from __future__ import annotations

import re
from pathlib import PurePosixPath


MAX_LOOKUP_BYTES = 5 * 1024 * 1024
SAVED_SEARCH_PATTERN = re.compile(r"\$[A-Za-z0-9_]+\(\)")


def slugify(value: str) -> str:
    normalized = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower()).strip("_")
    return normalized or "submission"


def build_query_filename(name: str) -> str:
    return f"{slugify(name)}.yml"


def sanitize_lookup_filename(filename: str) -> str:
    candidate = PurePosixPath(filename).name
    if candidate != filename or ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError("Invalid lookup filename.")
    if not candidate.lower().endswith(".csv"):
        raise ValueError("Lookup filename must end with .csv.")
    return candidate


def validate_query_payload(cql: str) -> None:
    match = SAVED_SEARCH_PATTERN.search(cql)
    if match:
        raise ValueError(
            f'Query contains a custom saved search reference "{match.group(0)}" which is not allowed.'
        )


def validate_lookup_content(csv_content: str) -> None:
    byte_length = len(csv_content.encode("utf-8"))
    if byte_length > MAX_LOOKUP_BYTES:
        raise ValueError("CSV content exceeds the 5 MB limit.")
    lines = [line for line in csv_content.splitlines() if line.strip()]
    if not lines:
        raise ValueError("CSV content must include a header row.")
