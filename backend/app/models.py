from __future__ import annotations

from pydantic import BaseModel, Field, field_validator


class ApiError(BaseModel):
    detail: str


class QuerySubmissionBase(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(..., min_length=1)
    author: str = Field(..., min_length=1, max_length=120)
    contact: str | None = Field(default=None, max_length=200)
    cql: str = Field(..., min_length=1)
    tags: list[str] = Field(default_factory=list)
    mitre_ids: list[str] = Field(default_factory=list)
    log_sources: list[str] = Field(default_factory=list)
    cs_required_modules: list[str] = Field(default_factory=list)
    explanation: str | None = None

    @field_validator("tags", "mitre_ids", "log_sources", "cs_required_modules")
    @classmethod
    def strip_string_lists(cls, values: list[str]) -> list[str]:
        return [value.strip() for value in values if value and value.strip()]

    @field_validator("name", "description", "author", "contact", "cql", "explanation")
    @classmethod
    def strip_scalar_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip()


class QuerySubmissionRequest(QuerySubmissionBase):
    pass


class LookupSubmissionBase(BaseModel):
    filename: str = Field(..., min_length=1, max_length=255)
    description: str = Field(..., min_length=1)
    author: str = Field(..., min_length=1, max_length=120)
    contact: str | None = Field(default=None, max_length=200)
    csv_content: str = Field(..., min_length=1)

    @field_validator("filename", "description", "author", "contact", "csv_content")
    @classmethod
    def strip_lookup_strings(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip()


class LookupSubmissionRequest(LookupSubmissionBase):
    pass


class QueryFilePayload(BaseModel):
    filename: str
    created_date: str | None = None
    parsed_content: dict


class QueriesResponse(BaseModel):
    queries: dict[str, QueryFilePayload]


class LookupFileResponse(BaseModel):
    name: str
    description: str
    author: str
    columns: list[str] = Field(default_factory=list)
    row_count: int = 0
    preview_rows: list[list[str]] = Field(default_factory=list)


class SubmissionResponse(BaseModel):
    status: str = "submitted"
    pull_request_url: str
    branch: str
