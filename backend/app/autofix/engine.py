"""DB-backed auto-fix engine: dry-run, apply and rollback over config text.

The engine is stateless with respect to *config computation* — callers pass the
config text in and get the patched text back. Rollback snapshots are now
persisted to the database so they survive restarts.
"""
from __future__ import annotations

import difflib
import uuid
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from ..analyzer.rules import analyze
from ..parser.parser import parse_config
from ..db import AsyncSessionLocal
from ..orm import FixVersionRow
from .models import AppliedFix, FixProposal, Version
from .registry import get_fix, has_fix
from . import fixes as _fixes  # noqa: F401  (import registers the fixers)
from .validator import validate


def _row_to_version(row: FixVersionRow) -> Version:
    return Version(
        version_id=row.version_id,
        created_at=row.created_at,
        content=row.content,
        note=row.note,
    )


class FixEngine:
    """Generates and applies safe patches for analyzer findings."""

    def __init__(self, session_factory: async_sessionmaker[AsyncSession] | None = None) -> None:
        self._sf = session_factory or AsyncSessionLocal

    # -- core ---------------------------------------------------------------

    def _candidate_findings(self, content: str, rule_ids: list[str] | None):
        findings = analyze(parse_config(content))
        wanted = set(rule_ids) if rule_ids else None
        for f in findings:
            if wanted is not None and f.rule_id not in wanted:
                continue
            if has_fix(f.rule_id):
                yield f

    def dry_run(
        self,
        content: str,
        rule_ids: list[str] | None = None,
        run_validation: bool = True,
    ) -> FixProposal:
        """Pure computation — no DB access."""
        working = content
        applied: list[AppliedFix] = []
        seen_noop: set[str] = set()

        for finding in self._candidate_findings(content, rule_ids):
            fixer = get_fix(finding.rule_id)
            assert fixer is not None
            new_content, summary = fixer(working, finding)
            if new_content == working:
                seen_noop.add(finding.rule_id)
                continue
            working = new_content
            applied.append(AppliedFix(
                rule_id=finding.rule_id, summary=summary, section=finding.section,
            ))

        skipped = sorted(seen_noop - {a.rule_id for a in applied})
        diff = self._unified_diff(content, working)
        proposal = FixProposal(
            original_content=content,
            proposed_content=working,
            diff=diff,
            applied=applied,
            skipped=skipped,
            changed=working != content,
        )
        if run_validation and proposal.changed:
            proposal.validation = validate(working)
        return proposal

    async def apply(
        self,
        content: str,
        rule_ids: list[str] | None = None,
        run_validation: bool = True,
    ) -> FixProposal:
        proposal = self.dry_run(content, rule_ids, run_validation)
        if not proposal.changed:
            return proposal
        version_id = uuid.uuid4().hex[:12]
        async with self._sf() as db:
            db.add(FixVersionRow(
                version_id=version_id,
                created_at=datetime.now(timezone.utc),
                content=content,
                note=f"before applying {len(proposal.applied)} fix(es)",
            ))
            await db.commit()
        proposal.version_id = version_id
        return proposal

    async def rollback(self, version_id: str) -> Version:
        async with self._sf() as db:
            row = await db.get(FixVersionRow, version_id)
            if row is None:
                raise KeyError(version_id)
            return _row_to_version(row)

    async def versions(self) -> list[Version]:
        async with self._sf() as db:
            result = await db.execute(
                select(FixVersionRow).order_by(FixVersionRow.created_at.desc())
            )
            return [_row_to_version(r) for r in result.scalars()]

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _unified_diff(before: str, after: str) -> str:
        return "".join(difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="haproxy.cfg", tofile="haproxy.cfg (fixed)",
        ))
