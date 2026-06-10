"""Periodic metrics collection with in-memory history and pub/sub fan-out."""
from __future__ import annotations

import asyncio
import time
from collections import deque
from typing import Any

from .client import StatsClientError, StatsSocketClient

# stat fields surfaced to the API; everything else is dropped to keep
# snapshots small enough to stream over WebSocket every interval
KEY_FIELDS = [
    "pxname", "svname", "type", "status", "scur", "smax", "stot",
    "rate", "req_rate", "qcur", "econ", "ereq", "eresp",
    "hrsp_1xx", "hrsp_2xx", "hrsp_3xx", "hrsp_4xx", "hrsp_5xx",
    "rtime", "ctime", "qtime", "ttime", "check_status", "lastchg", "weight",
]


def _trim_row(row: dict[str, str]) -> dict[str, str]:
    return {f: row.get(f, "") for f in KEY_FIELDS}


class MetricsCollector:
    def __init__(self, client: StatsSocketClient, interval: float = 2.0,
                 history_size: int = 900):
        self.client = client
        self.interval = interval
        self.history: deque[dict[str, Any]] = deque(maxlen=history_size)
        self._subscribers: set[asyncio.Queue] = set()
        self._task: asyncio.Task | None = None
        self.last_error: str | None = None

    async def collect_once(self) -> dict[str, Any]:
        try:
            rows = await self.client.show_stat()
            self.last_error = None
            snapshot = {
                "timestamp": time.time(),
                "ok": True,
                "rows": [_trim_row(r) for r in rows],
            }
        except StatsClientError as e:
            self.last_error = str(e)
            snapshot = {"timestamp": time.time(), "ok": False, "error": str(e), "rows": []}
        self.history.append(snapshot)
        for q in list(self._subscribers):
            if q.full():
                # slow consumer: drop its oldest snapshot rather than stall the loop
                try:
                    q.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            q.put_nowait(snapshot)
        return snapshot

    async def _run(self) -> None:
        while True:
            await self.collect_once()
            await asyncio.sleep(self.interval)

    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.get_event_loop().create_task(self._run())

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
            self._task = None

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=10)
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        self._subscribers.discard(q)

    @property
    def latest(self) -> dict[str, Any] | None:
        return self.history[-1] if self.history else None
