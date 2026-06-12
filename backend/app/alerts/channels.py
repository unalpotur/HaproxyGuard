"""Notification channels (webhook / Slack) and an in-memory channel registry.

Delivery uses the standard library only (no extra dependency); a failed send is
reported, never raised, so dispatch always returns a result per channel.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid

from .models import (
    Alert, AlertChannel, ChannelInput, ChannelSendResult, SEVERITY_ORDER,
)

_TIMEOUT = 5.0


def _eligible(alerts: list[Alert], min_severity: str) -> list[Alert]:
    cutoff = SEVERITY_ORDER.get(min_severity, 1)
    return [a for a in alerts if SEVERITY_ORDER.get(a.severity, 5) <= cutoff]


def build_payload(channel: AlertChannel, alerts: list[Alert]) -> dict:
    if channel.type == "slack":
        lines = [f"*HAProxy Guard* — {len(alerts)} alert(s)"]
        lines += [f"• [{a.severity}] {a.title}: {a.detail}" for a in alerts]
        return {"text": "\n".join(lines)}
    # generic webhook
    return {
        "source": "haproxy-guard",
        "count": len(alerts),
        "alerts": [a.model_dump(mode="json") for a in alerts],
    }


def send(channel: AlertChannel, alerts: list[Alert]) -> ChannelSendResult:
    eligible = _eligible(alerts, channel.min_severity)
    if not eligible:
        return ChannelSendResult(channel_id=channel.id, name=channel.name,
                                 ok=True, sent=0, message="no alerts at/above min_severity")
    data = json.dumps(build_payload(channel, eligible)).encode()
    req = urllib.request.Request(
        channel.url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return ChannelSendResult(channel_id=channel.id, name=channel.name,
                                     ok=200 <= resp.status < 300, sent=len(eligible),
                                     message=f"HTTP {resp.status}")
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return ChannelSendResult(channel_id=channel.id, name=channel.name,
                                 ok=False, sent=0, message=str(exc))


class ChannelRegistry:
    def __init__(self) -> None:
        self._channels: dict[str, AlertChannel] = {}

    def add(self, body: ChannelInput) -> AlertChannel:
        cid = "chan_" + uuid.uuid4().hex[:8]
        ch = AlertChannel(id=cid, name=body.name, type=body.type,
                          url=body.url, min_severity=body.min_severity)
        self._channels[cid] = ch
        return ch

    def list(self) -> list[AlertChannel]:
        return list(self._channels.values())

    def remove(self, channel_id: str) -> bool:
        return self._channels.pop(channel_id, None) is not None

    def dispatch(self, alerts: list[Alert]) -> list[ChannelSendResult]:
        return [send(ch, alerts) for ch in self._channels.values()]
