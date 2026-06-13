"""Async SQLAlchemy engine and session factory.

DATABASE_URL priority:
  1. DATABASE_URL env var  (e.g. postgresql+asyncpg://... in Docker)
  2. sqlite+aiosqlite:///./haproxy_guard.db  (local dev / tests)
"""
from __future__ import annotations

import os
from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

DATABASE_URL: str = os.environ.get(
    "DATABASE_URL",
    "sqlite+aiosqlite:///./haproxy_guard.db",
)

# echo=False in production; set HG_DB_ECHO=1 for SQL logging.
engine = create_async_engine(
    DATABASE_URL,
    echo=bool(os.environ.get("HG_DB_ECHO")),
    future=True,
)

AsyncSessionLocal: async_sessionmaker[AsyncSession] = async_sessionmaker(
    engine, expire_on_commit=False
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a session per request."""
    async with AsyncSessionLocal() as session:
        yield session


async def init_db() -> None:
    """Create all tables (dev / test helper).

    Production deployments should use ``alembic upgrade head`` instead.
    """
    from .orm import Base  # local import to avoid circular reference at module load

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """Dispose the engine connection pool (called on app shutdown)."""
    await engine.dispose()
