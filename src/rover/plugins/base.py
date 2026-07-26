"""src/rover/plugins/base.py — Scanner plugin Protocol and result data models."""

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass
class ScanResult:
    results: dict[str, Any]
    resolved_commit: str | None = None
    resolved_tags: str | None = None
    source: str = "fresh"  # 'fresh' | 'cached' | 'eol_api' | 'eol_cache'
    status: str | None = None  # 'cached' | 'fresh'


class ScannerPlugin(Protocol):
    """Protocol definition for all ROVER scanner plugins."""

    name: str
    supported_asset_types: set[str]

    def can_handle(self, target_type: str) -> bool:
        """Returns True if this plugin can process the specified target_type."""
        ...

    def scan(
        self,
        target_url: str,
        git_ref: str | None = None,
        target_type: str = "repo",
    ) -> ScanResult:
        """Executes a scan against the target and returns a ScanResult."""
        ...
