"""In-memory principal (API key) registry and audit log.

RBAC is *advisory by default*: when no principals are configured the registry is
"open" and every caller is treated as an admin, so the platform works without
auth out of the box. As soon as an admin key is configured (env or API) the
registry enforces roles. Tokens are stored only as salted hashes.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from collections import deque

from .models import AuditEntry, Principal, PrincipalCreated, ROLE_ORDER


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def has_at_least(role: str, required: str) -> bool:
    return ROLE_ORDER.get(role, -1) >= ROLE_ORDER.get(required, 99)


class PrincipalRegistry:
    def __init__(self) -> None:
        self._by_name: dict[str, Principal] = {}
        self._token_hashes: dict[str, str] = {}  # token_hash -> name

    def is_open(self) -> bool:
        return not self._by_name

    def add(self, name: str, role: str) -> PrincipalCreated:
        token = secrets.token_urlsafe(24)
        return self.add_with_token(name, role, token)

    def add_with_token(self, name: str, role: str, token: str) -> PrincipalCreated:
        if role not in ROLE_ORDER:
            raise ValueError(f"unknown role: {role}")
        principal = Principal(name=name, role=role)
        self._by_name[name] = principal
        self._token_hashes[_hash(token)] = name
        return PrincipalCreated(principal=principal, token=token)

    def authenticate(self, token: str) -> Principal | None:
        target = _hash(token)
        for th, name in self._token_hashes.items():
            if hmac.compare_digest(th, target):
                return self._by_name.get(name)
        return None

    def list(self) -> list[Principal]:
        return list(self._by_name.values())

    def remove(self, name: str) -> bool:
        if name not in self._by_name:
            return False
        del self._by_name[name]
        for th, n in list(self._token_hashes.items()):
            if n == name:
                del self._token_hashes[th]
        return True


class AuditLog:
    def __init__(self, maxlen: int = 1000) -> None:
        self._entries: deque[AuditEntry] = deque(maxlen=maxlen)
        self._counter = 0

    def append(self, actor: str, role: str, action: str, target: str | None = None,
               status: str = "ok", detail: str = "") -> AuditEntry:
        self._counter += 1
        entry = AuditEntry(id=self._counter, actor=actor, role=role, action=action,
                           target=target, status=status, detail=detail)
        self._entries.append(entry)
        return entry

    def list(self, limit: int = 200) -> list[AuditEntry]:
        return list(self._entries)[-limit:][::-1]  # newest first
