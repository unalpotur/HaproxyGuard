"""Data models for the Auto Fix Engine (Phase 5)."""
from __future__ import annotations

from datetime import datetime, timezone
from pydantic import BaseModel, Field


class AppliedFix(BaseModel):
    rule_id: str
    summary: str
    section: str | None = None


class Validation(BaseModel):
    """Result of validating a config (via `haproxy -c` when available)."""
    ran: bool
    ok: bool
    message: str = ""


class FixProposal(BaseModel):
    """Outcome of a dry-run or apply: the candidate config plus what changed."""
    original_content: str
    proposed_content: str
    diff: str
    applied: list[AppliedFix] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)  # rule_ids with no fixer / no change
    changed: bool = False
    validation: Validation | None = None
    version_id: str | None = None  # set when persisted by apply()


class Version(BaseModel):
    """A snapshot kept so an applied change can be rolled back."""
    version_id: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    content: str
    note: str = ""
