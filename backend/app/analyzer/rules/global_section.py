"""Rules about the global section and process hardening."""
from __future__ import annotations

from ..registry import Finding, rule, global_has
from ...parser.models import HaproxyConfig

CATEGORY = "hardening"


@rule
def missing_global_section(config: HaproxyConfig) -> list[Finding]:
    if config.global_section is not None:
        return []
    return [Finding(
        rule_id="HG054", severity="low", category=CATEGORY,
        title="No global section",
        detail="The configuration has no 'global' section.",
        suggestion="Add a 'global' section to set logging, tuning and process options.",
    )]


@rule
def running_as_root(config: HaproxyConfig) -> list[Finding]:
    g = config.global_section
    if g is None:
        return []
    has_user = any(d.keyword in ("user", "uid") for d in g.directives)
    has_group = any(d.keyword in ("group", "gid") for d in g.directives)
    if not has_user or not has_group:
        return [Finding(
            rule_id="HG055", severity="low", category=CATEGORY,
            title="Process may run as root",
            detail="global sets no 'user'/'group'; the worker may keep root privileges.",
            section="global",
            suggestion="Drop privileges with 'user haproxy' and 'group haproxy'.",
        )]
    return []


@rule
def no_chroot(config: HaproxyConfig) -> list[Finding]:
    if config.global_section is None:
        return []
    if not global_has(config, "chroot"):
        return [Finding(
            rule_id="HG056", severity="info", category=CATEGORY,
            title="No chroot configured",
            detail="global has no 'chroot'; sandboxing the process limits the blast radius of a compromise.",
            section="global",
            suggestion="Add 'chroot /var/lib/haproxy' (with a matching user/group).",
        )]
    return []
