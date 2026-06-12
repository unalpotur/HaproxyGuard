"""Analyzer rule catalog.

Importing this package registers every rule with the global RULES registry.
Public surface kept stable for the rest of the app: `analyze`, `Finding`.
"""
from ..registry import analyze, Finding, rule, RULES  # noqa: F401

# Importing the category modules triggers their @rule registrations.
from . import (  # noqa: F401,E402
    correctness,
    reliability,
    security,
    tls,
    performance,
    observability,
    best_practices,
    global_section,
)

__all__ = ["analyze", "Finding", "rule", "RULES"]
