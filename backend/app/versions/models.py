"""Models for config versioning."""
from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel


class ConfigVersion(BaseModel):
    id: str
    label: str = ""
    message: str = ""
    author: str = "anonymous"
    created_at: datetime
    content_hash: str
    size: int
    parent_id: str | None = None


class SaveVersionInput(BaseModel):
    content: str
    label: str = ""
    message: str = ""


class VersionContent(BaseModel):
    version: ConfigVersion
    content: str


class DiffResult(BaseModel):
    a: str
    b: str
    diff: str
