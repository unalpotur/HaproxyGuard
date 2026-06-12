"""Models for the Security Center (Phase 7)."""
from __future__ import annotations

from pydantic import BaseModel, Field


class ControlSpec(BaseModel):
    """Catalog entry describing a security control and its tunable params."""
    id: str
    name: str
    category: str  # rate-limit | ddos | geo | admin
    description: str
    params: dict[str, object] = Field(default_factory=dict)


class ControlRequest(BaseModel):
    id: str
    params: dict[str, object] = Field(default_factory=dict)


class ResolvedControl(BaseModel):
    id: str
    name: str
    category: str
    params: dict[str, object] = Field(default_factory=dict)


class PresetSpec(BaseModel):
    id: str
    name: str
    description: str
    controls: list[ControlRequest] = Field(default_factory=list)


class GeneratedConfig(BaseModel):
    preset: str | None = None
    controls: list[ResolvedControl] = Field(default_factory=list)
    global_lines: list[str] = Field(default_factory=list)
    frontend_lines: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    snippet: str = ""


class ControlStatus(BaseModel):
    id: str
    name: str
    category: str
    present: bool
    sections: list[str] = Field(default_factory=list)
    detail: str = ""


class SecurityPosture(BaseModel):
    controls: list[ControlStatus] = Field(default_factory=list)
    present_count: int = 0
    total: int = 0
    score: int = 0  # 0-100
    recommendations: list[str] = Field(default_factory=list)
