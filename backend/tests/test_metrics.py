import asyncio

import pytest

from app.metrics.client import (
    StatsClientError, StatsSocketClient, parse_show_info, parse_show_stat,
)
from app.metrics.collector import MetricsCollector

SHOW_STAT = (
    "# pxname,svname,qcur,scur,rate,status,hrsp_2xx,hrsp_5xx,rtime,\n"
    "web,FRONTEND,,12,34,OPEN,1000,5,,\n"
    "app,srv1,0,3,10,UP,800,2,12,\n"
    "app,BACKEND,0,3,10,UP,800,2,12,\n"
)

SHOW_INFO = "Name: HAProxy\nVersion: 2.9.6\nUptime_sec: 120\n"


async def test_parse_show_stat():
    rows = parse_show_stat(SHOW_STAT)
    assert len(rows) == 3
    assert rows[0]["pxname"] == "web"
    assert rows[0]["svname"] == "FRONTEND"
    assert rows[1]["status"] == "UP"
    assert rows[2]["hrsp_5xx"] == "2"


async def test_parse_show_stat_rejects_garbage():
    with pytest.raises(StatsClientError):
        parse_show_stat("not csv output")


async def test_parse_show_info():
    info = parse_show_info(SHOW_INFO)
    assert info["Version"] == "2.9.6"
    assert info["Uptime_sec"] == "120"


@pytest.fixture
async def fake_stats_server():
    """TCP server that mimics the HAProxy stats socket protocol."""
    async def handle(reader, writer):
        command = (await reader.readline()).decode().strip()
        reply = SHOW_STAT if command == "show stat" else SHOW_INFO
        writer.write(reply.encode())
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    yield f"127.0.0.1:{port}"
    server.close()
    await server.wait_closed()


async def test_client_against_fake_server(fake_stats_server):
    client = StatsSocketClient(fake_stats_server)
    rows = await client.show_stat()
    assert rows[0]["pxname"] == "web"
    info = await client.show_info()
    assert info["Name"] == "HAProxy"


async def test_client_connection_refused():
    client = StatsSocketClient("127.0.0.1:1", timeout=1)
    with pytest.raises(StatsClientError):
        await client.show_stat()


async def test_collector_snapshot_and_subscribe(fake_stats_server):
    collector = MetricsCollector(StatsSocketClient(fake_stats_server))
    queue = collector.subscribe()
    snap = await collector.collect_once()
    assert snap["ok"] and len(snap["rows"]) == 3
    assert snap["rows"][0]["pxname"] == "web"
    assert queue.get_nowait() is snap
    assert collector.latest is snap


async def test_collector_records_errors():
    collector = MetricsCollector(StatsSocketClient("127.0.0.1:1", timeout=1))
    snap = await collector.collect_once()
    assert not snap["ok"]
    assert collector.last_error
