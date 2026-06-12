"""Models for the AI Assistant (Phase 8)."""
from __future__ import annotations

from pydantic import BaseModel, Field


class RootCause(BaseModel):
    title: str
    severity: str  # critical | high | medium | low | info
    category: str
    evidence: str


class Recommendation(BaseModel):
    action: str
    rationale: str
    priority: str  # high | medium | low


class LogSummary(BaseModel):
    total_lines: int = 0
    parsed: int = 0
    error_rate: float = 0.0
    status_classes: dict[str, int] = Field(default_factory=dict)  # "2xx".."5xx"
    slow_count: int = 0
    slow_threshold_ms: int = 1000
    avg_response_ms: float | None = None
    backends_by_error: list[dict] = Field(default_factory=list)  # {backend, errors, total}


class AssistantReport(BaseModel):
    risk_score: int = 0  # 0 (healthy) .. 100 (critical)
    risk_level: str = "low"  # low | medium | high | critical
    summary: str = ""
    root_causes: list[RootCause] = Field(default_factory=list)
    recommendations: list[Recommendation] = Field(default_factory=list)
    log_summary: LogSummary | None = None
    used_llm: bool = False
    llm_narrative: str | None = None
