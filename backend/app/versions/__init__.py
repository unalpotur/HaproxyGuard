"""Config versioning & diff (bonus): git-style history with restore."""
from .store import VersionStore
from .models import (
    ConfigVersion, DiffResult, SaveVersionInput, VersionContent,
)

__all__ = [
    "VersionStore", "ConfigVersion", "DiffResult", "SaveVersionInput",
    "VersionContent",
]
