"""The Auto Fix Engine: dry-run, apply and rollback over config text."""
from __future__ import annotations

import difflib
import uuid

from ..analyzer.rules import analyze
from ..parser.parser import parse_config
from .models import AppliedFix, FixProposal, Version
from .registry import get_fix, has_fix
from . import fixes as _fixes  # noqa: F401  (import registers the fixers)
from .validator import validate


class FixEngine:
    """Generates and applies safe patches for analyzer findings.

    The engine is stateless with respect to *config storage* — callers pass the
    config text in and get the patched text back — but it does keep an in-memory
    version store so an applied change can be rolled back to its prior state.
    """

    def __init__(self) -> None:
        self._versions: dict[str, Version] = {}

    # -- core ---------------------------------------------------------------

    def _candidate_findings(self, content: str, rule_ids: list[str] | None):
        findings = analyze(parse_config(content))
        wanted = set(rule_ids) if rule_ids else None
        for f in findings:
            if wanted is not None and f.rule_id not in wanted:
                continue
            if has_fix(f.rule_id):
                yield f

    def dry_run(self, content: str, rule_ids: list[str] | None = None,
                run_validation: bool = True) -> FixProposal:
        working = content
        applied: list[AppliedFix] = []
        skipped: list[str] = []
        seen_noop: set[str] = set()
        requested_with_fix: set[str] = set()

        for finding in self._candidate_findings(content, rule_ids):
            requested_with_fix.add(finding.rule_id)
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

        # rule_ids that were requested/findable but produced no change
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

    def apply(self, content: str, rule_ids: list[str] | None = None,
              run_validation: bool = True) -> FixProposal:
        proposal = self.dry_run(content, rule_ids, run_validation)
        if not proposal.changed:
            return proposal
        # store the PRE-change content so it can be restored
        version_id = uuid.uuid4().hex[:12]
        self._versions[version_id] = Version(
            version_id=version_id, content=content,
            note=f"before applying {len(proposal.applied)} fix(es)",
        )
        proposal.version_id = version_id
        return proposal

    def rollback(self, version_id: str) -> Version:
        version = self._versions.get(version_id)
        if version is None:
            raise KeyError(version_id)
        return version

    def versions(self) -> list[Version]:
        return sorted(self._versions.values(), key=lambda v: v.created_at, reverse=True)

    # -- helpers ------------------------------------------------------------

    @staticmethod
    def _unified_diff(before: str, after: str) -> str:
        return "".join(difflib.unified_diff(
            before.splitlines(keepends=True),
            after.splitlines(keepends=True),
            fromfile="haproxy.cfg", tofile="haproxy.cfg (fixed)",
        ))
