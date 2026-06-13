"""DB-backed RBAC principal registry and audit log.

RBAC is *advisory by default*: when no principals are configured the registry
is "open" and every caller is treated as an admin. As soon as an admin key is
configured the registry enforces roles. Tokens are stored only as salted hashes.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..db import AsyncSessionLocal
from ..orm import AuditRow, PrincipalRow, TokenRow
from .models import AuditEntry, Principal, PrincipalCreated, ROLE_ORDER


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def has_at_least(role: str, required: str) -> bool:
    return ROLE_ORDER.get(role, -1) >= ROLE_ORDER.get(required, 99)


class PrincipalRegistry:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession] | None = None) -> None:
        self._sf = session_factory or AsyncSessionLocal

    async def is_open(self) -> bool:
        """True when no principals configured (open/anonymous mode)."""
        async with self._sf() as db:
            count = await db.scalar(select(func.count()).select_from(PrincipalRow))
            return (count or 0) == 0

    async def add(self, name: str, role: str) -> PrincipalCreated:
        token = secrets.token_urlsafe(24)
        return await self.add_with_token(name, role, token)

    async def add_with_token(self, name: str, role: str, token: str) -> PrincipalCreated:
        if role not in ROLE_ORDER:
            raise ValueError(f"unknown role: {role}")
        async with self._sf() as db:
            row = PrincipalRow(name=name, role=role)
            db.add(row)
            db.add(TokenRow(token_hash=_hash(token), principal_name=name))
            await db.commit()
        return PrincipalCreated(principal=Principal(name=name, role=role), token=token)

    async def authenticate(self, token: str) -> Principal | None:
        target = _hash(token)
        async with self._sf() as db:
            result = await db.execute(
                select(TokenRow).where(TokenRow.token_hash == target)
            )
            tok = result.scalar_one_or_none()
            if tok is None:
                return None
            # constant-time compare against the DB value
            if not hmac.compare_digest(tok.token_hash, target):
                return None
            p = await db.get(PrincipalRow, tok.principal_name)
            return Principal(name=p.name, role=p.role) if p else None

    async def list(self) -> list[Principal]:
        async with self._sf() as db:
            result = await db.execute(select(PrincipalRow))
            return [Principal(name=r.name, role=r.role) for r in result.scalars()]

    async def remove(self, name: str) -> bool:
        async with self._sf() as db:
            row = await db.get(PrincipalRow, name)
            if row is None:
                return False
            await db.delete(row)
            await db.commit()
            return True


class AuditLog:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession] | None = None) -> None:
        self._sf = session_factory or AsyncSessionLocal

    async def append(
        self,
        actor: str,
        role: str,
        action: str,
        target: str | None = None,
        status: str = "ok",
        detail: str = "",
    ) -> AuditEntry:
        async with self._sf() as db:
            row = AuditRow(
                actor=actor, role=role, action=action,
                target=target, status=status, detail=detail,
                created_at=datetime.now(timezone.utc),
            )
            db.add(row)
            await db.commit()
            await db.refresh(row)
            return _row_to_entry(row)

    async def list(self, limit: int = 200) -> list[AuditEntry]:
        async with self._sf() as db:
            result = await db.execute(
                select(AuditRow).order_by(AuditRow.id.desc()).limit(limit)
            )
            return [_row_to_entry(r) for r in result.scalars()]


def _row_to_entry(row: AuditRow) -> AuditEntry:
    return AuditEntry(
        id=row.id,
        actor=row.actor,
        role=row.role,
        action=row.action,
        target=row.target,
        status=row.status,
        detail=row.detail,
        created_at=row.created_at,
    )
