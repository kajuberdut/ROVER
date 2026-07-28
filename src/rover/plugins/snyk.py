"""src/rover/plugins/snyk.py — Snyk scanner plugin for open-source dependency (OSS), SAST, and container image scanning."""

import json
import logging
import os
import subprocess
import tempfile
from typing import Any

from testcontainers.core.container import (
    DockerContainer,  # type: ignore[import-untyped]
)

from rover import db, vault
from rover.plugins.base import ScanResult

logger = logging.getLogger(__name__)


def parse_snyk_oss_output(json_text: str) -> tuple[list[dict[str, Any]], str | None]:
    """Parses Snyk OSS test JSON output into a tuple of (vulnerabilities, manifest_error_msg)."""
    if not json_text or not json_text.strip():
        return [], None
    try:
        json_start = json_text.find("{")
        json_end = json_text.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            clean_json = json_text[json_start:json_end]
            data = json.loads(clean_json)
            if isinstance(data, dict):
                if data.get("ok") is False and data.get("error"):
                    err_msg = str(data.get("error"))
                    if (
                        "Could not detect supported target files" in err_msg
                        or "No supported target files" in err_msg
                        or "Could not detect package manager" in err_msg
                    ):
                        logger.info(f"Snyk scan info: {err_msg}")
                        return [], err_msg
                    raise Exception(f"Snyk error: {err_msg}")
                return data.get("vulnerabilities", []), None
            elif isinstance(data, list):
                vulns = []
                for item in data:
                    vulns.extend(item.get("vulnerabilities", []))
                return vulns, None
    except Exception as e:
        if "Snyk error:" in str(e):
            raise
        logger.warning(f"Failed to parse Snyk OSS JSON output: {e}")
    return [], None


def parse_snyk_code_output(json_text: str) -> list[dict[str, Any]]:
    """Parses Snyk Code SAST JSON output into a normalized list of issue dicts."""
    if not json_text or not json_text.strip():
        return []
    try:
        json_start = json_text.find("{")
        json_end = json_text.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            clean_json = json_text[json_start:json_end]
            data = json.loads(clean_json)
            if isinstance(data, dict):
                runs = data.get("runs", [])
                issues = []
                for run in runs:
                    results = run.get("results", [])
                    issues.extend(results)
                if issues:
                    return issues
                issues_list: list[dict[str, Any]] = list(data.get("issues", []))
                return issues_list
    except Exception as e:
        logger.warning(f"Failed to parse Snyk Code JSON output: {e}")
    return []


class SnykScannerPlugin:
    """Scanner plugin that executes Snyk OSS dependency, SAST, and container image scans using Testcontainers."""

    name = "snyk"
    display_name = "Snyk Security"
    icon = "🐶"
    description = "Snyk Open-Source and Container Image Vulnerability Scanner"
    template_name: str | None = "report_snyk.html"
    supported_asset_types = {"snyk", "repo", "image"}

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
        duration_str = (
            f"{duration_seconds}s"
            if (duration_seconds is not None and duration_seconds < 60)
            else (
                f"{duration_seconds // 60}m {duration_seconds % 60:02d}s"
                if duration_seconds is not None
                else None
            )
        )
        avg_str = (
            f"{int(avg_duration_seconds)}s"
            if (avg_duration_seconds is not None and avg_duration_seconds < 60)
            else (
                f"{int(avg_duration_seconds) // 60}m {int(avg_duration_seconds) % 60:02d}s"
                if avg_duration_seconds is not None
                else None
            )
        )

        time_label = ""
        if status == "running" and duration_str:
            time_label = f" ({duration_str}" + (f", avg {avg_str})" if avg_str else ")")
        elif status == "queued" and avg_str:
            time_label = f" (avg {avg_str})"
        elif status == "completed" and duration_str:
            time_label = f" [{duration_str}]"

        if status == "failed":
            return {
                "label": f"🐶 ⚠️ Snyk Failed{time_label}",
                "status": "failed",
                "bg": "#d32f2f",
                "border": "#b71c1c",
                "color": "white",
                "tooltip": f"Snyk Scan Failed: {error_message or 'Execution error'}",
                "duration_str": duration_str,
                "avg_str": avg_str,
            }
        if status in ("queued", "running"):
            return {
                "label": f"🐶 ⏳ Snyk {status}{time_label}",
                "status": status,
                "bg": "#ff9800",
                "border": "#e65100",
                "color": "white",
                "busy": True,
                "duration_str": duration_str,
                "avg_str": avg_str,
            }
        if results:
            vulns = results.get("vulnerabilities", [])
            if results.get("unsupported_manifest") or results.get("manifest_error"):
                return {
                    "label": f"🐶 ⚠️ Unsupported{time_label}",
                    "status": "unsupported",
                    "bg": "#f57c00",
                    "border": "#e65100",
                    "color": "white",
                    "tooltip": f"Snyk Notice: {results.get('manifest_error') or 'Unsupported package manager'}",
                    "duration_str": duration_str,
                    "avg_str": avg_str,
                }
            if len(vulns) > 0:
                return {
                    "label": f"🐶 {len(vulns)} Snyk{time_label}",
                    "status": "has_vulns",
                    "count": len(vulns),
                    "bg": "#4b45a9",
                    "border": "#363181",
                    "color": "white",
                    "duration_str": duration_str,
                    "avg_str": avg_str,
                }
            return {
                "label": f"🐶 Snyk Clean{time_label}",
                "status": "clean",
                "bg": "transparent",
                "border": "#4b45a9",
                "color": "#4b45a9",
                "duration_str": duration_str,
                "avg_str": avg_str,
            }
        return {
            "label": "🐶 No Snyk Data",
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
        product_id: str | None = None,
        credential_id: str | None = None,
    ) -> ScanResult:
        logger.info(
            f"Starting Snyk scan for {target_type} {target_url} (ref {git_ref or 'HEAD'})"
        )

        runner = subprocess_runner or subprocess.run
        dock_cls = container_cls or DockerContainer

        # Fetch Snyk Token from OpenBao or environment variable
        snyk_token: str | None = None
        if credential_id and credential_id != "auto":
            cred = db.get_credential_by_id(credential_id)
            if cred and cred.get("type") in ("snyk_token", "generic"):
                snyk_token = db.get_unmasked_secret(
                    name=cred["name"],
                    scope=cred["scope"],
                    product_id=cred.get("product_id"),
                )

        if not snyk_token:
            snyk_token, _ = db.get_unmasked_secret_by_type_info(
                credential_type="snyk_token", product_id=product_id
            )

        if not snyk_token:
            snyk_token = os.getenv("SNYK_TOKEN")

        from rover import config

        snyk_img = config.get_scanner_image("snyk")
        container = dock_cls(snyk_img)

        if snyk_token:
            container.with_env("SNYK_TOKEN", snyk_token)

        commit_hash = "latest"
        tags_str = None
        oss_vulns: list[dict[str, Any]] = []
        sast_issues: list[dict[str, Any]] = []
        manifest_errors: list[str] = []

        if target_type == "image":
            container.with_volume_mapping(
                "/var/run/docker.sock", "/var/run/docker.sock", "rw"
            )
            container.with_command(f"snyk container test {target_url} --json")
            try:
                container.start()
                client = container.get_docker_client()
                wrapped = container.get_wrapped_container()
                if wrapped:
                    res_wait = client.client.containers.get(wrapped.id)
                    res_wait.wait()
                logs = container.get_logs()
                stdout = logs[0].decode("utf-8") if logs and logs[0] else ""
                oss_vulns, img_err = parse_snyk_oss_output(stdout)
                if img_err:
                    manifest_errors.append(img_err)
            finally:
                try:
                    container.stop()
                except Exception as stop_err:
                    logger.debug(f"Container stop notice: {stop_err}")
        else:
            with tempfile.TemporaryDirectory() as tmpdir:
                # Clone target git repository
                auth_url = vault.get_authenticated_git_url(
                    target_url, product_id=product_id, credential_id=credential_id
                )
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
                        e.stderr.decode("utf-8")
                        if isinstance(e.stderr, bytes)
                        else str(e.stderr)
                    )
                    logger.error(f"Failed to clone repository for Snyk scan: {err_msg}")
                    raise Exception(
                        f"Failed to clone target repository for Snyk: {err_msg}"
                    ) from e

                if git_ref:
                    try:
                        runner(
                            ["git", "checkout", git_ref],
                            cwd=tmpdir,
                            check=True,
                            capture_output=True,
                            env=env,
                        )
                    except subprocess.CalledProcessError as e:
                        err_msg = (
                            e.stderr.decode("utf-8")
                            if isinstance(e.stderr, bytes)
                            else str(e.stderr)
                        )
                        logger.error(f"Failed to checkout ref {git_ref}: {err_msg}")

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

                # Determine target manifest files to scan
                configured_targets = (
                    getattr(config.settings.scanners, "snyk_target_files", []) or []
                )
                targets_to_scan = list(configured_targets)

                if not targets_to_scan:
                    # Auto-discover manifests in subdirectories
                    MANIFEST_NAMES = {
                        "pyproject.toml",
                        "requirements.txt",
                        "Pipfile",
                        "poetry.lock",
                        "setup.py",
                        "package.json",
                        "pom.xml",
                        "build.gradle",
                        "go.mod",
                        "Cargo.toml",
                    }
                    for root, _dirs, files in os.walk(tmpdir):
                        if ".git" in root or ".venv" in root or "node_modules" in root:
                            continue
                        for file in files:
                            if file in MANIFEST_NAMES:
                                rel_path = os.path.relpath(
                                    os.path.join(root, file), tmpdir
                                )
                                targets_to_scan.append(rel_path)

                all_oss_vulns: list[dict[str, Any]] = []

                if targets_to_scan:
                    logger.info(f"Snyk scanning target files: {targets_to_scan}")
                    for target_file in targets_to_scan:
                        sub_container = dock_cls(snyk_img)
                        if snyk_token:
                            sub_container.with_env("SNYK_TOKEN", snyk_token)
                        sub_container.with_env(
                            "COMMAND", f"snyk test --file=/app/{target_file} --json"
                        )
                        sub_container.with_volume_mapping(tmpdir, "/app", "ro")
                        sub_container.with_command(
                            f"snyk test --file=/app/{target_file} --json"
                        )
                        try:
                            sub_container.start()
                            client = sub_container.get_docker_client()
                            wrapped = sub_container.get_wrapped_container()
                            if wrapped:
                                res_wait = client.client.containers.get(wrapped.id)
                                res_wait.wait()
                            sub_logs = sub_container.get_logs()
                            sub_stdout = (
                                sub_logs[0].decode("utf-8")
                                if sub_logs and sub_logs[0]
                                else ""
                            )
                            sub_vulns, sub_err_msg = parse_snyk_oss_output(sub_stdout)
                            all_oss_vulns.extend(sub_vulns)
                            if sub_err_msg:
                                manifest_errors.append(f"{target_file}: {sub_err_msg}")
                        except Exception as sub_err:
                            logger.warning(
                                f"Snyk sub-target scan for {target_file} notice: {sub_err}"
                            )
                        finally:
                            try:
                                sub_container.stop()
                            except Exception as stop_err:
                                logger.debug(f"Sub-container stop notice: {stop_err}")
                else:
                    container.with_volume_mapping(tmpdir, "/app", "ro")
                    container.with_command("snyk test --json --all-projects")
                    try:
                        container.start()
                        client = container.get_docker_client()
                        wrapped = container.get_wrapped_container()
                        if wrapped:
                            result = client.client.containers.get(wrapped.id)
                            result.wait()
                        logs = container.get_logs()
                        oss_stdout = logs[0].decode("utf-8") if logs and logs[0] else ""
                        all_oss_vulns, root_err = parse_snyk_oss_output(oss_stdout)
                        if root_err:
                            manifest_errors.append(root_err)
                    finally:
                        try:
                            container.stop()
                        except Exception as stop_err:
                            logger.debug(f"Container stop notice: {stop_err}")

                oss_vulns = all_oss_vulns
                no_manifests_found = not targets_to_scan and not oss_vulns

        manifest_error_summary = "; ".join(manifest_errors) if manifest_errors else None
        unsupported_manifest = bool(manifest_errors)

        combined_results = {
            "snyk_oss": {"vulnerabilities": oss_vulns},
            "snyk_sast": {"issues": sast_issues},
            "vulnerabilities": oss_vulns,
            "issues": sast_issues,
            "no_manifests_found": no_manifests_found
            if "no_manifests_found" in locals()
            else False,
            "unsupported_manifest": unsupported_manifest,
            "manifest_error": manifest_error_summary,
        }

        return ScanResult(
            results=combined_results,
            resolved_commit=commit_hash,
            resolved_tags=tags_str,
        )
