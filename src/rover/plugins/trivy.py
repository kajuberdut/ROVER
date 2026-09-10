"""src/rover/plugins/trivy.py — Trivy scanner plugin for dependency and container image CVE scans."""

import json
import logging
import re
import subprocess
import tempfile
from typing import Any, cast

# ruff: noqa: S603, S607
from testcontainers.core.container import DockerContainer  # type: ignore

from rover import vault
from rover.plugins.base import ScanResult

logger = logging.getLogger(__name__)


def _check_and_raise_trivy_notices(stdout: str, stderr: str) -> None:
    """Parses Trivy output logs for update notices and records admin notifications."""
    combined_logs = f"{stdout}\n{stderr}"

    match = re.search(
        r"Version\s+([vV]?\d+\.\d+\.\d+)\s+of\s+Trivy\s+is\s+now\s+available,\s+current\s+version\s+is\s+([vV]?\d+\.\d+\.\d+)",
        combined_logs,
        re.IGNORECASE,
    )
    if match:
        available_version = match.group(1)
        current_version = match.group(2)

        try:
            from rover import config, db
            from rover.scanner_updates import (
                extract_version_from_image_ref,
                is_newer_version,
            )

            configured_image = config.get_scanner_image("trivy")
            configured_ver = (
                extract_version_from_image_ref(configured_image) or current_version
            )

            if is_newer_version(available_version, configured_ver):
                title = f"Trivy Scanner Update Available (v{available_version})"
                message = (
                    f"Version {available_version} of Trivy is now available. "
                    f"The current version running in ROVER is {configured_ver}."
                )
                db.create_admin_notification(
                    title=title,
                    message=message,
                    category="scanner_update",
                    source_tool="trivy",
                    metadata_dict={
                        "current_version": configured_ver,
                        "available_version": available_version,
                    },
                )
                logger.info(
                    f"Recorded admin notification for Trivy update: v{configured_ver} -> v{available_version}"
                )
            else:
                db.dismiss_outdated_scanner_notifications("trivy", configured_ver)
                logger.info(
                    f"Auto-dismissed outdated Trivy update notifications: configured v{configured_ver} >= available v{available_version}"
                )
        except (KeyError, ValueError, RuntimeError, TypeError) as e:
            # Catch metadata payload construction errors so scanner notices do not interrupt execution
            logger.warning(f"Failed to record Trivy update notification: {e}")


def resolve_image_hash(
    image_name: str, subprocess_runner: Any | None = None
) -> str | None:
    """Resolves container image digest (e.g., sha256:...) using Skopeo or Docker Registry API."""
    logger.info(f"Resolving image hash for {image_name}")
    runner = subprocess_runner or subprocess.run

    # Attempt 1: Skopeo inspect if available
    try:
        url = f"docker://{image_name}"
        res = runner(
            ["skopeo", "inspect", url],
            capture_output=True,
            text=True,
            timeout=15,
            check=True,
        )
        data = json.loads(res.stdout)
        digest = data.get("Digest")
        if digest:
            return str(digest)
    except (
        subprocess.SubprocessError,
        json.JSONDecodeError,
        KeyError,
        OSError,
        ValueError,
        Exception,
    ) as e:
        # Skopeo CLI fallback: catch subprocess execution failures, missing binary, or JSON decode issues to safely fall back to Docker Registry API
        logger.debug(f"Skopeo inspect skipped or failed for {image_name}: {e}")

    # Attempt 2: Direct Docker Registry v2 API query via urllib
    try:
        import urllib.error
        import urllib.request

        repo = image_name.split(":")[0]
        tag = image_name.split(":")[1] if ":" in image_name else "latest"
        if "/" not in repo:
            repo = f"library/{repo}"

        auth_url = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{repo}:pull"
        req = urllib.request.Request(auth_url)  # noqa: S310
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            token = json.loads(resp.read().decode())["token"]

        manifest_url = f"https://registry-1.docker.io/v2/{repo}/manifests/{tag}"
        req = urllib.request.Request(  # noqa: S310
            manifest_url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json",
            },
        )
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            digest = resp.headers.get("Docker-Content-Digest")

            if digest:
                logger.info(
                    f"Resolved image digest via Docker Registry API for {image_name}: {digest}"
                )
                return str(digest)
    except (
        urllib.error.URLError,
        json.JSONDecodeError,
        KeyError,
        OSError,
        ValueError,
    ) as e:
        # Catch network timeouts, HTTP errors, or JSON authentication token parsing failures
        logger.warning(f"Docker Registry API lookup failed for {image_name}: {e}")

    return None


def parse_cyclonedx_components(cdx_json_str: str) -> list[dict[str, Any]]:
    """Parses a CycloneDX JSON string into a list of standardized component dicts."""
    components: list[dict[str, Any]] = []
    if not cdx_json_str or not cdx_json_str.strip():
        return components

    try:
        data = json.loads(cdx_json_str)
        for comp in data.get("components", []) or []:
            name = comp.get("name")
            if not name:
                continue
            version = comp.get("version", "unknown")
            purl = comp.get("purl")
            cpe = comp.get("cpe")

            license_spdx = None
            licenses = comp.get("licenses", []) or []
            if licenses and isinstance(licenses, list):
                lic_obj = licenses[0]
                if isinstance(lic_obj, dict):
                    if "license" in lic_obj and isinstance(lic_obj["license"], dict):
                        license_spdx = lic_obj["license"].get("id") or lic_obj[
                            "license"
                        ].get("name")
                    elif "expression" in lic_obj:
                        license_spdx = lic_obj["expression"]

            comp_type = comp.get("type", "library")
            components.append(
                {
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "cpe": cpe,
                    "license_spdx": license_spdx,
                    "component_type": comp_type,
                }
            )
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
        # Catch invalid JSON syntax or unexpected component dictionary schema structures
        logger.warning(f"Failed to parse CycloneDX components: {e}")

    return components


def parse_spdx_components(spdx_json_str: str) -> list[dict[str, Any]]:
    """Parses an SPDX JSON string into a list of standardized component dicts."""
    components: list[dict[str, Any]] = []
    if not spdx_json_str or not spdx_json_str.strip():
        return components

    try:
        data = json.loads(spdx_json_str)
        for pkg in data.get("packages", []) or []:
            name = pkg.get("name")
            if not name:
                continue
            version = pkg.get("versionInfo", "unknown")
            license_spdx = pkg.get("licenseConcluded") or pkg.get("licenseDeclared")
            if license_spdx == "NOASSERTION":
                license_spdx = None

            purl = None
            cpe = None
            for ref in pkg.get("externalRefs", []) or []:
                ref_type = ref.get("referenceType")
                if ref_type == "purl":
                    purl = ref.get("referenceLocator")
                elif ref_type in ("cpe22Type", "cpe23Type"):
                    cpe = ref.get("referenceLocator")

            components.append(
                {
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "cpe": cpe,
                    "license_spdx": license_spdx,
                    "component_type": "library",
                }
            )
    except (json.JSONDecodeError, KeyError, TypeError, AttributeError) as e:
        # Catch invalid JSON syntax or missing package fields in SPDX payload
        logger.warning(f"Failed to parse SPDX components: {e}")

    return components


def _clone_and_resolve_git_repo(
    target_url: str, git_ref: str | None, tmpdir: str, runner: Any
) -> tuple[str, str | None]:
    """Clones the repository at target_url, checks out git_ref, and resolves commit hash and tags."""
    import os

    clean_url, clean_ref = vault.parse_git_url_and_ref(target_url, git_ref)
    auth_url = vault.get_authenticated_git_url(clean_url)
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    try:
        runner(
            ["git", "clone", auth_url, tmpdir],
            check=True,
            capture_output=True,
            env=env,
        )
    except subprocess.CalledProcessError as e:
        err_msg = (
            e.stderr.decode("utf-8") if isinstance(e.stderr, bytes) else str(e.stderr)
        )
        logger.error(f"Failed to clone repository '{clean_url}': {err_msg}")
        raise Exception(f"Failed to clone repository '{clean_url}'") from e

    if clean_ref:
        try:
            runner(
                ["git", "checkout", clean_ref],
                cwd=tmpdir,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            err_msg = (
                e.stderr.decode("utf-8")
                if isinstance(e.stderr, bytes)
                else str(e.stderr)
            )
            logger.error(f"Failed to checkout ref {clean_ref}: {err_msg}")
            raise Exception(
                f"Git reference '{clean_ref}' not found in '{clean_url}'. "
                f"Please verify exact branch, tag (e.g. 'release-1.16.0' or 'v1.16.0'), or commit hash."
            ) from e

    try:
        res = runner(
            ["git", "rev-parse", "HEAD"],
            cwd=tmpdir,
            check=True,
            capture_output=True,
            text=True,
        )
        commit_hash = res.stdout.strip()

        res = runner(
            ["git", "tag", "--points-at", "HEAD"],
            cwd=tmpdir,
            check=True,
            capture_output=True,
            text=True,
        )
        tags = [t.strip() for t in res.stdout.split("\n") if t.strip()]
        tags_str = ", ".join(tags) if tags else None
    except subprocess.CalledProcessError as e:
        logger.warning(f"Failed to capture git metadata: {e}")
        commit_hash = "unknown"
        tags_str = None

    return commit_hash, tags_str


def _record_vulnerabilities_to_ledger(
    scan_results: dict[str, Any], release_asset_id: str
) -> None:
    """Records vulnerability findings into the centralized asset_vulnerabilities ledger."""
    from rover import db

    try:
        for res_item in scan_results.get("Results", []) or []:
            for v in res_item.get("Vulnerabilities", []) or []:
                v_id = v.get("VulnerabilityID")
                p_name = v.get("PkgName")
                i_ver = v.get("InstalledVersion")
                sev = str(v.get("Severity", "UNKNOWN")).upper()
                f_ver = v.get("FixedVersion")
                if v_id and p_name and i_ver:
                    db.record_vulnerability(
                        release_asset_id=release_asset_id,
                        scanner_name="trivy",
                        vulnerability_id=v_id,
                        package_name=p_name,
                        installed_version=i_ver,
                        severity=sev,
                        fixed_version=f_ver,
                    )
    except Exception as e:
        # Catch database connection/insertion errors or vulnerability ledger mapping errors
        logger.warning(f"Failed to record asset vulnerabilities: {e}")


def _extract_and_record_sbom(
    scan_results: dict[str, Any],
    target_type: str,
    release_asset_id: str | None,
    json_str: str,
) -> tuple[str, list[dict[str, Any]]]:
    """Extracts software components from Trivy results and records SBOM to database."""
    from rover import db

    sbom_fmt = "spdx" if target_type == "repo" else "cyclonedx"
    sbom_comps: list[dict[str, Any]] = []

    if scan_results:
        for res_item in scan_results.get("Results", []) or []:
            for pkg in res_item.get("Packages", []) or []:
                p_name = pkg.get("Name")
                if not p_name:
                    continue
                p_ver = pkg.get("Version", "unknown")
                purl = (
                    pkg.get("Identifier", {}).get("PURL")
                    if isinstance(pkg.get("Identifier"), dict)
                    else None
                )
                cpe = (
                    pkg.get("Identifier", {}).get("CPE")
                    if isinstance(pkg.get("Identifier"), dict)
                    else None
                )
                lic_spdx = None
                licenses = pkg.get("Licenses", []) or []
                if licenses and isinstance(licenses, list):
                    lic_spdx = str(licenses[0])

                sbom_comps.append(
                    {
                        "name": p_name,
                        "version": p_ver,
                        "purl": purl,
                        "cpe": cpe,
                        "license_spdx": lic_spdx,
                        "component_type": (
                            "library" if target_type == "repo" else "container"
                        ),
                    }
                )

            # Fallback: Extract packages from Vulnerabilities list if Packages list was omitted
            seen_names = {c["name"] for c in sbom_comps}
            for vuln in res_item.get("Vulnerabilities", []) or []:
                p_name = vuln.get("PkgName")
                if not p_name or p_name in seen_names:
                    continue
                p_ver = vuln.get("InstalledVersion", "unknown")
                purl = (
                    vuln.get("PkgIdentifier", {}).get("PURL")
                    if isinstance(vuln.get("PkgIdentifier"), dict)
                    else None
                )
                cpe = (
                    vuln.get("PkgIdentifier", {}).get("CPE")
                    if isinstance(vuln.get("PkgIdentifier"), dict)
                    else None
                )
                seen_names.add(p_name)
                sbom_comps.append(
                    {
                        "name": p_name,
                        "version": p_ver,
                        "purl": purl,
                        "cpe": cpe,
                        "license_spdx": None,
                        "component_type": (
                            "library" if target_type == "repo" else "container"
                        ),
                    }
                )

        if release_asset_id and (sbom_comps or json_str):
            try:
                db.add_sbom(
                    release_asset_id=release_asset_id,
                    format_name=sbom_fmt,
                    spec_version="1.6" if sbom_fmt == "cyclonedx" else "2.3",
                    raw_payload=json_str,
                    components=sbom_comps,
                )
            except Exception as e:
                # Catch database connection/insertion errors or payload parsing errors
                logger.warning(f"Failed to record SBOM data: {e}")
                # Catch component dictionary payload formatting or database insertion errors
                logger.warning(f"Failed to record SBOM data: {e}")

    return sbom_fmt, sbom_comps


class TrivyScannerPlugin:
    """Scanner plugin that executes Trivy dependency and container image CVE scans."""

    name = "trivy"
    display_name = "Trivy Scanner"
    icon = "shield"
    description = "Container & Repository Vulnerability Scanner"
    template_name: str | None = "report.html"
    supported_asset_types = {"repo", "image"}

    def can_handle(self, target_type: str) -> bool:
        return target_type in self.supported_asset_types

    def get_badge_info(
        self,
        results: dict[str, Any] | None,
        status: str | None,
        error_message: str | None = None,
        duration_seconds: int | None = None,
        avg_duration_seconds: int | None = None,
    ) -> dict[str, Any]:
        duration_str = f"{duration_seconds}s" if duration_seconds is not None else None
        avg_str = f"{int(avg_duration_seconds)}s" if avg_duration_seconds else None

        time_label = ""
        if duration_str:
            time_label = f" ({duration_str}" + (f", avg {avg_str})" if avg_str else ")")
        elif avg_str:
            time_label = f" (avg {avg_str})"

        if status == "failed":
            return {
                "label": f"Trivy Failed{time_label}",
                "status": "failed",
                "bg": "#d32f2f",
                "border": "#b71c1c",
                "color": "white",
                "tooltip": f"Trivy Scan Failed: {error_message or 'Execution error'}",
                "duration_str": duration_str,
                "avg_str": avg_str,
            }
        if status in ("queued", "running"):
            return {
                "label": f"Trivy {status.title()}{time_label}",
                "status": status,
                "bg": "#ff9800",
                "border": "#e65100",
                "color": "white",
                "busy": True,
                "duration_str": duration_str,
                "avg_str": avg_str,
            }
        if results:
            critical = 0
            high = 0
            medium = 0
            low = 0
            for r in results.get("Results", []) or []:
                for v in r.get("Vulnerabilities", []) or []:
                    sev = str(v.get("Severity", "")).upper()
                    if sev == "CRITICAL":
                        critical += 1
                    elif sev == "HIGH":
                        high += 1
                    elif sev == "MEDIUM":
                        medium += 1
                    elif sev == "LOW":
                        low += 1
            total = critical + high + medium + low
            if total > 0:
                return {
                    "label": f"{total} CVEs{time_label}",
                    "status": "has_vulns",
                    "critical": critical,
                    "high": high,
                    "medium": medium,
                    "low": low,
                    "total": total,
                    "bg": "#d32f2f"
                    if critical > 0
                    else ("#f57c00" if high > 0 else "#fbc02d"),
                    "border": "#b71c1c"
                    if critical > 0
                    else ("#e65100" if high > 0 else "#f57f17"),
                    "color": "white" if (critical > 0 or high > 0) else "#333",
                    "duration_str": duration_str,
                    "avg_str": avg_str,
                }
            return {
                "label": f"CVE Clean{time_label}",
                "status": "clean",
                "bg": "transparent",
                "border": "#388e3c",
                "color": "#388e3c",
                "duration_str": duration_str,
                "avg_str": avg_str,
            }
        return {
            "label": "No CVE Data",
            "status": "none",
            "duration_str": duration_str,
            "avg_str": avg_str,
        }

    def scan(
        self,
        target_url: str,
        git_ref: str | None = None,
        target_type: str = "repo",
        container_cls: Any | None = None,
        subprocess_runner: Any | None = None,
        vex_path: str | None = None,
        release_asset_id: str | None = None,
    ) -> ScanResult:
        logger.info(
            f"Starting Trivy scan for {target_type} {target_url} (ref {git_ref or 'HEAD'})"
        )
        runner = subprocess_runner or subprocess.run
        dock_cls = container_cls or DockerContainer

        with tempfile.TemporaryDirectory() as tmpdir:
            commit_hash = "latest"
            tags_str = None
            image_target = target_url

            if target_type == "repo":
                commit_hash, tags_str = _clone_and_resolve_git_repo(
                    target_url, git_ref, tmpdir, runner
                )
            elif target_type == "image":
                if git_ref and ":" not in image_target.split("/")[-1]:
                    image_target = f"{target_url}:{git_ref}"
                tags_str = image_target

            from rover import config

            trivy_img = config.get_scanner_image("trivy")
            container = dock_cls(trivy_img)

            container.with_env("TRIVY_CACHE_DIR", "/trivy-cache")
            container.with_volume_mapping(
                "trivy-vulnerability-db-cache", "/trivy-cache", "rw"
            )
            container.with_volume_mapping(
                "/var/run/docker.sock", "/var/run/docker.sock", "ro"
            )

            vex_flag = f"--vex {vex_path} " if vex_path else ""
            if target_type == "repo":
                container.with_volume_mapping(tmpdir, "/src", "ro")
                container.with_command(f"fs /src --list-all-pkgs {vex_flag}-f json")
            else:
                container.with_command(
                    f"image {image_target} --list-all-pkgs {vex_flag}-f json"
                )

            try:
                container.start()

                client = container.get_docker_client()
                result = client.client.containers.get(
                    container.get_wrapped_container().id
                )

                exit_code = result.wait()["StatusCode"]

                logs = container.get_logs()
                stdout = logs[0].decode("utf-8")
                stderr = logs[1].decode("utf-8")

                logger.info(f"Trivy stdout (first 200 chars): {stdout[:200]}")
                logger.info(f"Trivy stderr: {stderr}")

                _check_and_raise_trivy_notices(stdout, stderr)

                if exit_code != 0:
                    logger.warning(
                        f"Trivy scan exited with code {exit_code}. Stderr: {stderr}"
                    )

                try:
                    json_start = stdout.find("{")
                    json_end = stdout.rfind("}") + 1
                    if json_start >= 0 and json_end > json_start:
                        json_str = stdout[json_start:json_end]
                        scan_results = cast(dict[str, Any], json.loads(json_str))
                    else:
                        if exit_code != 0:
                            raise Exception(f"Trivy failed with exit code {exit_code}")
                        scan_results = {"Results": []}
                        json_str = "{}"

                    if release_asset_id and scan_results:
                        _record_vulnerabilities_to_ledger(
                            scan_results, release_asset_id
                        )

                    sbom_fmt, sbom_comps = _extract_and_record_sbom(
                        scan_results, target_type, release_asset_id, json_str
                    )

                    return ScanResult(
                        results=scan_results,
                        resolved_commit=commit_hash,
                        resolved_tags=tags_str,
                        source="fresh",
                        sbom_payload=json_str if json_str else None,
                        sbom_format=sbom_fmt,
                        sbom_components=sbom_comps,
                    )

                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse Trivy JSON output. Error: {e}")
                    logger.error(f"Raw output: {stdout}")
                    raise Exception("Failed to parse vulnerability report") from e

            finally:
                container.stop()
