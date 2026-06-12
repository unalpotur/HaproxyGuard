"""Models for the Alerting subsystem (Phase 9.5)."""
from __future__ import annotations

from datetime import datetime, timezone
from pydantic import BaseModel, Field

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class Alert(BaseModel):
    severity: str  # critical | high | medium | low | info
    source: str    # config | tls | logs | cluster
    title: str
    detail: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class Thresholds(BaseModel):
    error_rate: float = 0.05        # alert when log error rate ≥ this
    cert_expiry_days: int = 30      # alert when a readable cert expires within N days
    alert_on_drift: bool = True     # cluster config drift
    alert_on_offline: bool = True   # any offline node


class EvaluateInput(BaseModel):
    content: str
    logs: str | None = None
    read_certs: bool = False
    thresholds: Thresholds = Field(default_factory=Thresholds)
    include_cluster: bool = True


class AlertChannel(BaseModel):
    id: str
    name: str
    type: str           # webhook | slack
    url: str
    min_severity: str = "high"


class ChannelInput(BaseModel):
    name: str
    type: str = "webhook"
    url: str
    min_severity: str = "high"


class ChannelSendResult(BaseModel):
    channel_id: str
    name: str
    ok: bool
    sent: int
    message: str = ""


class DispatchResult(BaseModel):
    alerts: list[Alert] = Field(default_factory=list)
    results: list[ChannelSendResult] = Field(default_factory=list)
