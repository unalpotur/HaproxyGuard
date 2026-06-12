"""Auto Fix Engine (Phase 5): safe patch generation with dry-run + rollback."""
from .engine import FixEngine
from .models import AppliedFix, FixProposal, Validation, Version
from .registry import FIXES, has_fix

__all__ = [
    "FixEngine", "FixProposal", "AppliedFix", "Validation", "Version",
    "FIXES", "has_fix",
]
