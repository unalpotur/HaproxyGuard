"""DB-backed notification channel registry.

Delivery (HTTP webhook / Slack) is still synchronous urllib — the network call
itself is fast and not on the hot path. Only the registry state (CRUD) is
persisted to the database.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..db import AsyncSessionLocal
from ..orm import AlertChannelRow
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


def _row_to_channel(row: AlertChannelRow) -> AlertChannel:
    return AlertChannel(
        id=row.id, name=row.name, type=row.type,
        url=row.url, min_severity=row.min_severity,
    )


class ChannelRegistry:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession] | None = None) -> None:
        self._sf = session_factory or AsyncSessionLocal

    async def add(self, body: ChannelInput) -> AlertChannel:
        cid = "chan_" + uuid.uuid4().hex[:8]
        async with self._sf() as db:
            row = AlertChannelRow(
                id=cid, name=body.name, type=body.type,
                url=body.url, min_severity=body.min_severity,
            )
            db.add(row)
            await db.commit()
            return _row_to_channel(row)

    async def list(self) -> list[AlertChannel]:
        async with self._sf() as db:
            result = await db.execute(select(AlertChannelRow))
            return [_row_to_channel(r) for r in result.scalars()]

    async def remove(self, channel_id: str) -> bool:
        async with self._sf() as db:
            row = await db.get(AlertChannelRow, channel_id)
            if row is None:
                return False
            await db.delete(row)
            await db.commit()
            return True

    async def dispatch(self, alerts: list[Alert]) -> list[ChannelSendResult]:
        channels = await self.list()
        return [send(ch, alerts) for ch in channels]
