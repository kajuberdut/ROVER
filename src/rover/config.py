import os
from dataclasses import dataclass, field

import tomlkit

CONFIG_FILE = "config.toml"

DEFAULT_TRIVY_IMAGE = "aquasec/trivy@sha256:ee940acbf1f58ebadb42d01434ce4609530bf1b52536afbd1eee66cd7123c5c9"
DEFAULT_SEMGREP_IMAGE = "semgrep/semgrep@sha256:155f999d01d02b33aa5a8db9186eb20dcd0154ce1a0ac6fce8d80674d0ace235"
DEFAULT_HELM_IMAGE = "alpine/helm@sha256:f92964e7ecaa7effe87dd6c3dfed25fa3175e80fe8eb0fc8fd669291dea389d2"
DEFAULT_SNYK_IMAGE = "snyk/snyk:alpine@sha256:3fe9af4ae66ae714e5e8816ae132d3972dd65db25c261973f1e1778991f90ab6"


DEFAULT_CONFIG_TOML = f"""# R.O.V.E.R Configuration File
# This file manages system-wide scanner execution, container image pins, and web interface defaults.
# You can edit this file directly or via the System Administration menu in the Web UI (/config).

[scanner]
# Maximum execution time in seconds allowed for a single container security or SAST scan job.
# Default: 600 (10 minutes). Recommended range: 60 to 3600 seconds.
timeout_seconds = 600

# Duration in hours that a completed scan report is cached for a specific Git commit SHA-1.
# Default: 8 hours. Recommended range: 1 to 72 hours.
cache_ttl_hours = 8

[scanners]
# Pinned container image references used by ROVER worker plugins for security scanning.
# To update a scanner tool, replace the tag or sha256 digest below after inspecting official release notes.

# Trivy vulnerability scanner container image (e.g., aquasec/trivy:0.69.3 or pinned sha256 digest)
trivy_image = "{DEFAULT_TRIVY_IMAGE}"

# Semgrep SAST scanner container image (e.g., semgrep/semgrep:1.100.0 or pinned sha256 digest)
semgrep_image = "{DEFAULT_SEMGREP_IMAGE}"

# Helm CLI tool container image for chart linting and template rendering (e.g., alpine/helm:3.16.2)
helm_image = "{DEFAULT_HELM_IMAGE}"

# Snyk scanner container image for open-source dependency (OSS) and SAST code scanning
snyk_image = "{DEFAULT_SNYK_IMAGE}"

[ui]
# The primary navigation tab selected by default on the dashboard.
# Valid options: "repo" (Source Repositories), "image" (Container Images), "major_components" (Major Components)
default_tab = "repo"

[features]
# Enables or disables the user invitation workflow.
# When set to false, generating, sending, and accepting user invitation links is disabled.
allow_user_invites = true
"""  # noqa: S608


@dataclass
class ScannerConfig:
    timeout_seconds: int = 600
    cache_ttl_hours: int = 8


@dataclass
class ScannersConfig:
    trivy_image: str = DEFAULT_TRIVY_IMAGE
    semgrep_image: str = DEFAULT_SEMGREP_IMAGE
    helm_image: str = DEFAULT_HELM_IMAGE
    snyk_image: str = DEFAULT_SNYK_IMAGE
    snyk_target_files: list[str] = field(default_factory=list)


@dataclass
class UIConfig:
    default_tab: str = "repo"


@dataclass
class FeaturesConfig:
    allow_user_invites: bool = True


@dataclass
class RoverConfig:
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    scanners: ScannersConfig = field(default_factory=ScannersConfig)
    ui: UIConfig = field(default_factory=UIConfig)
    features: FeaturesConfig = field(default_factory=FeaturesConfig)


def load_config() -> RoverConfig:
    """Load configuration from config.toml, creating it with defaults if missing."""
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            f.write(DEFAULT_CONFIG_TOML)
        return RoverConfig()

    with open(CONFIG_FILE, "r") as f:
        doc = tomlkit.loads(f.read())

    scanner_data = doc.get("scanner", {})
    scanners_data = doc.get("scanners", {})
    ui_data = doc.get("ui", {})
    features_data = doc.get("features", {})

    scanner_config = ScannerConfig(
        timeout_seconds=int(scanner_data.get("timeout_seconds", 600)),
        cache_ttl_hours=int(scanner_data.get("cache_ttl_hours", 8)),
    )
    raw_snyk_targets = scanners_data.get("snyk_target_files", [])
    snyk_targets = (
        list(raw_snyk_targets) if isinstance(raw_snyk_targets, (list, tuple)) else []
    )
    scanners_config = ScannersConfig(
        trivy_image=scanners_data.get("trivy_image", DEFAULT_TRIVY_IMAGE),
        semgrep_image=scanners_data.get("semgrep_image", DEFAULT_SEMGREP_IMAGE),
        helm_image=scanners_data.get("helm_image", DEFAULT_HELM_IMAGE),
        snyk_image=scanners_data.get("snyk_image", DEFAULT_SNYK_IMAGE),
        snyk_target_files=snyk_targets,
    )
    ui_config = UIConfig(default_tab=ui_data.get("default_tab", "repo"))
    features_config = FeaturesConfig(
        allow_user_invites=bool(features_data.get("allow_user_invites", True))
    )

    return RoverConfig(
        scanner=scanner_config,
        scanners=scanners_config,
        ui=ui_config,
        features=features_config,
    )


def save_raw_config(raw_toml: str) -> None:
    """Validate and save raw TOML string to config.toml, preserving user comments."""
    tomlkit.loads(raw_toml)
    with open(CONFIG_FILE, "w") as f:
        f.write(raw_toml)


def read_raw_config() -> str:
    """Read the raw TOML string from config.toml for editing in the UI."""
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_CONFIG_TOML
    with open(CONFIG_FILE, "r") as f:
        return f.read()


# Global settings instance
settings = load_config()


def get_scanner_image(scanner_name: str) -> str:
    """Returns the configured scanner container image reference.

    Raises ValueError if the image reference is not set or empty.
    """
    image_ref = getattr(settings.scanners, f"{scanner_name}_image", None)
    if not image_ref or not str(image_ref).strip():
        raise ValueError(
            f"Configuration error: [scanners.{scanner_name}_image] is not set in config.toml. "
            f"Please specify a valid container image tag or pinned digest."
        )
    return str(image_ref).strip()
