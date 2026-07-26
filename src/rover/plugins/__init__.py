"""src/rover/plugins/__init__.py — Scanner plugin registry for ROVER."""

from typing import Sequence

from rover.plugins.base import ScannerPlugin, ScanResult
from rover.plugins.eol import EolComponentScannerPlugin
from rover.plugins.helm import HelmScannerPlugin
from rover.plugins.semgrep import SemgrepScannerPlugin
from rover.plugins.trivy import TrivyScannerPlugin

_REGISTRY: list[ScannerPlugin] = [
    TrivyScannerPlugin(),
    SemgrepScannerPlugin(),
    EolComponentScannerPlugin(),
    HelmScannerPlugin(),
]


def register_plugin(plugin: ScannerPlugin) -> None:
    """Registers a new ScannerPlugin instance into the global registry."""
    _REGISTRY.append(plugin)


def list_plugins() -> Sequence[ScannerPlugin]:
    """Returns a list of all registered scanner plugins."""
    return tuple(_REGISTRY)


def get_plugin_for_job(target_type: str) -> ScannerPlugin:
    """Finds and returns the registered ScannerPlugin capable of handling the target_type.

    Raises ValueError if no matching plugin is found.
    """
    for plugin in _REGISTRY:
        if plugin.can_handle(target_type):
            return plugin
    raise ValueError(f"No scanner plugin registered for target_type '{target_type}'")


__all__ = [
    "EolComponentScannerPlugin",
    "HelmScannerPlugin",
    "ScanResult",
    "ScannerPlugin",
    "SemgrepScannerPlugin",
    "TrivyScannerPlugin",
    "get_plugin_for_job",
    "list_plugins",
    "register_plugin",
]
