"""Git-style version history for HAProxy configs with unified diff + restore.

Each save is content-addressed (a sha256 prefix) and linked to its parent,
forming a linear history. Kept in memory here, but the model mirrors a git log
so it could be backed by a real repository later. Saving identical content to
the current tip is a no-op (returns the existing tip), like `git commit` with no
changes.
"""
from __future__ import annotations

import difflib
import hashlib
from datetime import datetime, timezone

from .models import ConfigVersion


def _hash(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()[:12]


class VersionStore:
    def __init__(self) -> None:
        self._versions: list[ConfigVersion] = []
        self._content: dict[str, str] = {}
        self._counter = 0

    def save(self, content: str, label: str = "", message: str = "",
             author: str = "anonymous") -> ConfigVersion:
        if self._versions and self._content[self._versions[-1].id] == content:
            return self._versions[-1]  # no change since the tip
        self._counter += 1
        vid = f"v{self._counter}"
        parent = self._versions[-1].id if self._versions else None
        version = ConfigVersion(
            id=vid, label=label, message=message, author=author,
            created_at=datetime.now(timezone.utc), content_hash=_hash(content),
            size=len(content), parent_id=parent,
        )
        self._versions.append(version)
        self._content[vid] = content
        return version

    def list(self) -> list[ConfigVersion]:
        return list(reversed(self._versions))  # newest first

    def get(self, version_id: str) -> ConfigVersion | None:
        return next((v for v in self._versions if v.id == version_id), None)

    def content(self, version_id: str) -> str | None:
        return self._content.get(version_id)

    def diff(self, a: str, b: str) -> str:
        ca, cb = self._content.get(a), self._content.get(b)
        if ca is None or cb is None:
            raise KeyError("unknown version id")
        return "".join(difflib.unified_diff(
            ca.splitlines(keepends=True), cb.splitlines(keepends=True),
            fromfile=a, tofile=b))

    def restore(self, version_id: str, author: str = "anonymous") -> ConfigVersion | None:
        content = self._content.get(version_id)
        if content is None:
            return None
        return self.save(content, label="restore",
                         message=f"restore of {version_id}", author=author)
