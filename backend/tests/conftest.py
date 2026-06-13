"""Shared pytest fixtures for HAProxy Guard backend tests.

All tests that need a database get an isolated SQLite in-memory session via
the ``db`` fixture — no PostgreSQL required to run the suite.
"""
from __future__ import annotations

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.orm import Base
from app.db import AsyncSessionLocal  # noqa: F401 (imported to allow monkeypatching)


# ---------------------------------------------------------------------------
# In-memory SQLite engine — created fresh for every test module / session.
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="session")
async def engine():
    """One engine per test session — tables created once."""
    eng = create_async_engine("sqlite+aiosqlite:///:memory:", future=True)
    async with eng.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield eng
    await eng.dispose()


@pytest_asyncio.fixture
async def db(engine) -> AsyncSession:
    """Transactional test session — rolled back after each test."""
    async with engine.begin() as conn:
        session = AsyncSession(bind=conn, expire_on_commit=False)
        yield session
        await session.rollback()
        # Ensure we delete all data between tests for isolation
        for table in reversed(Base.metadata.sorted_tables):
            await session.execute(table.delete())
        await session.commit()
        await session.close()


@pytest_asyncio.fixture
def session_factory(engine) -> async_sessionmaker[AsyncSession]:
    """A session factory bound to the in-memory engine for injecting into stores."""
    return async_sessionmaker(engine, expire_on_commit=False)


# ---------------------------------------------------------------------------
# FastAPI test client — wires stores to the in-memory DB.
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture
async def client(session_factory, monkeypatch):
    """AsyncClient pointed at the FastAPI app with DB wired to SQLite."""
    import app.db as db_mod
    import app.versions.store as vs_mod
    import app.authz.registry as authz_mod
    import app.alerts.channels as ch_mod
    import app.cluster.registry as cl_mod
    import app.autofix.engine as fx_mod

    # Patch module-level AsyncSessionLocal in each store so they use our engine.
    monkeypatch.setattr(db_mod, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(vs_mod, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(authz_mod, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(ch_mod, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(cl_mod, "AsyncSessionLocal", session_factory)
    monkeypatch.setattr(fx_mod, "AsyncSessionLocal", session_factory)

    from app.main import app as fastapi_app

    async with AsyncClient(
        transport=ASGITransport(app=fastapi_app), base_url="http://test"
    ) as ac:
        yield ac
