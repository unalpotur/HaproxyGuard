"""Client for the HAProxy Runtime API (stats socket).

Supports TCP (`host:port`) and unix socket (`/path/to/sock` or `unix@/path`)
addresses. Only read-only commands are used here; see ROADMAP note on
read-only vs read-write socket separation.
"""
from __future__ import annotations

import asyncio


class StatsClientError(Exception):
    pass


class StatsSocketClient:
    def __init__(self, address: str, timeout: float = 5.0):
        self.address = address
        self.timeout = timeout

    async def _connect(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        addr = self.address
        if addr.startswith("unix@"):
            addr = addr[len("unix@"):]
        if addr.startswith("/"):
            return await asyncio.open_unix_connection(addr)
        host, _, port = addr.rpartition(":")
        if not port.isdigit():
            raise StatsClientError(f"invalid stats address: {self.address!r}")
        return await asyncio.open_connection(host or "127.0.0.1", int(port))

    async def send_command(self, command: str) -> str:
        try:
            reader, writer = await asyncio.wait_for(self._connect(), self.timeout)
        except (OSError, asyncio.TimeoutError) as e:
            raise StatsClientError(f"cannot connect to {self.address}: {e}") from e
        try:
            writer.write(command.encode() + b"\n")
            await writer.drain()
            data = await asyncio.wait_for(reader.read(), self.timeout)
            return data.decode(errors="replace")
        except (OSError, asyncio.TimeoutError) as e:
            raise StatsClientError(f"command {command!r} failed: {e}") from e
        finally:
            writer.close()

    async def show_stat(self) -> list[dict[str, str]]:
        return parse_show_stat(await self.send_command("show stat"))

    async def show_info(self) -> dict[str, str]:
        return parse_show_info(await self.send_command("show info"))


def parse_show_stat(raw: str) -> list[dict[str, str]]:
    """Parse `show stat` CSV output into one dict per proxy/server row."""
    lines = [l for l in raw.splitlines() if l.strip()]
    if not lines:
        return []
    header_line = lines[0]
    if not header_line.startswith("# "):
        raise StatsClientError("unexpected 'show stat' output (missing CSV header)")
    fields = header_line[2:].rstrip(",").split(",")
    rows = []
    for line in lines[1:]:
        values = line.rstrip(",").split(",")
        rows.append({f: v for f, v in zip(fields, values)})
    return rows


def parse_show_info(raw: str) -> dict[str, str]:
    info = {}
    for line in raw.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            info[key.strip()] = value.strip()
    return info
