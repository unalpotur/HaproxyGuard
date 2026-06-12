"""Alerting (Phase 9.5): evaluate deployment state and notify channels."""
from .rules import evaluate
from .channels import ChannelRegistry, build_payload, send
from .models import (
    Alert, AlertChannel, ChannelInput, ChannelSendResult, DispatchResult,
    EvaluateInput, Thresholds,
)

__all__ = [
    "evaluate", "ChannelRegistry", "build_payload", "send",
    "Alert", "AlertChannel", "ChannelInput", "ChannelSendResult",
    "DispatchResult", "EvaluateInput", "Thresholds",
]
