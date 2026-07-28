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

    name: str  # Machine name, e.g. "trivy", "semgrep", "snyk", "helm"
    display_name: str  # User-facing label, e.g. "Snyk Security", "Semgrep SAST"
    icon: str  # Emoji/Icon, e.g. "🐶", "🔍", "🛡️"
    description: str
    template_name: str | None  # Optional template filename for report page tabs
    supported_asset_types: set[str]

    def can_handle(self, target_type: str) -> bool:
        """Returns True if this plugin can process the specified target_type."""
        ...

    def scan(
        self,
        target_url: str,
        git_ref: str | None = None,
        target_type: str = "repo",
        *args: Any,
        **kwargs: Any,
    ) -> ScanResult:
        """Executes a scan against the target and returns a ScanResult."""
        ...

    def get_badge_info(
        self,
        results: dict[str, Any] | None,
        status: str | None,
        error_message: str | None = None,
        duration_seconds: int | None = None,
        avg_duration_seconds: int | None = None,
    ) -> dict[str, Any]:
        """Returns a dict containing badge attributes: label, count, status_class, tooltip, etc."""
        ...
