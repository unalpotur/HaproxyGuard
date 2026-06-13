"""Git-style version history for HAProxy configs — DB-backed (async).

Each save is content-addressed (sha256 prefix) and linked to its parent,
forming a linear history. The external id is ``v{seq}`` where seq is the
auto-incremented integer primary key. Saving identical content to the current
tip is a no-op (returns the existing tip), like ``git commit`` with no changes.
"""
from __future__ import annotations

import difflib
import hashlib
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..db import AsyncSessionLocal
from ..orm import ConfigContentRow, ConfigVersionRow
from .models import ConfigVersion


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:12]


def _row_to_version(row: ConfigVersionRow) -> ConfigVersion:
    return ConfigVersion(
        id=f"v{row.seq}",
        label=row.label,
        message=row.message,
        author=row.author,
        created_at=row.created_at,
        content_hash=row.content_hash,
        size=row.size,
        parent_id=f"v{row.parent_seq}" if row.parent_seq else None,
    )


def _parse_id(version_id: str) -> int | None:
    """'v5' → 5; returns None if malformed."""
    try:
        return int(version_id.lstrip("v"))
    except ValueError:
        return None


class VersionStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession] | None = None) -> None:
        self._sf = session_factory or AsyncSessionLocal

    # ------------------------------------------------------------------

    async def save(
        self,
        content: str,
        label: str = "",
        message: str = "",
        author: str = "anonymous",
    ) -> ConfigVersion:
        async with self._sf() as db:
            # No-op if content matches current tip.
            tip = await self._tip_row(db)
            if tip is not None:
                tip_content = await db.get(ConfigContentRow, tip.seq)
                if tip_content and tip_content.content == content:
                    return _row_to_version(tip)

            parent_seq = tip.seq if tip else None
            row = ConfigVersionRow(
                label=label,
                message=message,
                author=author,
                created_at=datetime.now(timezone.utc),
                content_hash=_hash(content),
                size=len(content),
                parent_seq=parent_seq,
            )
            db.add(row)
            await db.flush()  # populate seq

            db.add(ConfigContentRow(version_seq=row.seq, content=content))
            await db.commit()
            await db.refresh(row)
            return _row_to_version(row)

    async def list(self) -> list[ConfigVersion]:
        async with self._sf() as db:
            result = await db.execute(
                select(ConfigVersionRow).order_by(ConfigVersionRow.seq.desc())
            )
            return [_row_to_version(r) for r in result.scalars()]

    async def get(self, version_id: str) -> ConfigVersion | None:
        seq = _parse_id(version_id)
        if seq is None:
            return None
        async with self._sf() as db:
            row = await db.get(ConfigVersionRow, seq)
            return _row_to_version(row) if row else None

    async def content(self, version_id: str) -> str | None:
        seq = _parse_id(version_id)
        if seq is None:
            return None
        async with self._sf() as db:
            row = await db.get(ConfigContentRow, seq)
            return row.content if row else None

    async def diff(self, a: str, b: str) -> str:
        ca, cb = await self.content(a), await self.content(b)
        if ca is None or cb is None:
            raise KeyError("unknown version id")
        return "".join(difflib.unified_diff(
            ca.splitlines(keepends=True), cb.splitlines(keepends=True),
            fromfile=a, tofile=b,
        ))

    async def restore(self, version_id: str, author: str = "anonymous") -> ConfigVersion | None:
        c = await self.content(version_id)
        if c is None:
            return None
        return await self.save(c, label="restore",
                               message=f"restore of {version_id}", author=author)

    # ------------------------------------------------------------------
    async def _tip_row(self, db: AsyncSession) -> ConfigVersionRow | None:
        result = await db.execute(
            select(ConfigVersionRow).order_by(ConfigVersionRow.seq.desc()).limit(1)
        )
        return result.scalar_one_or_none()
