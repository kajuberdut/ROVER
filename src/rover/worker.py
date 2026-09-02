import asyncio
import json
import logging
import os
from typing import Any

os.environ["TESTCONTAINERS_RYUK_DISABLED"] = "true"

from rover.db import (
    claim_next_job,
    claim_next_semgrep_job,
    claim_next_snyk_job,
    get_completed_semgrep_job_by_commit,
    get_completed_snyk_job_by_commit,
    update_job_status,
    update_semgrep_job_status,
    update_snyk_job_status,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def process_job(
    job_id: str, target_url: str, git_ref: str | None = None, target_type: str = "repo"
) -> None:
    logger.info(
        f"Starting job {job_id} for {target_type} {target_url} at ref {git_ref}"
    )

    # Job is already set to 'running' via claim_next_job.

    try:
        from rover import plugins

        plugin = plugins.get_plugin_for_job(target_type)

        if target_type == "major_component":
            # We expect target_url to be the name, and git_ref to be the version
            if not git_ref:
                raise ValueError(
                    "Major Component scan requires a version string in git_ref"
                )
            res = await asyncio.to_thread(plugin.scan, target_url, git_ref, target_type)
        else:
            if target_type == "image":
                from rover import scanner
                from rover.db import (
                    add_repository,
                    create_semgrep_job,
                    get_ci_image_metadata,
                    get_image_by_name,
                    update_image_hash,
                )

                image_record = get_image_by_name(target_url)
                if image_record:
                    image_hash = image_record.get("image_hash")
                    if not image_hash:
                        image_hash = await asyncio.to_thread(
                            scanner.resolve_image_hash, target_url
                        )
                        if image_hash:
                            update_image_hash(image_record["id"], image_hash)
                            logger.info(
                                f"Resolved image hash for {target_url}: {image_hash}"
                            )

                    if image_hash:
                        # Check CI metadata to see if we should run Semgrep
                        ci_metadata = get_ci_image_metadata(image_hash)
                        if ci_metadata and ci_metadata.get("repo_uri"):
                            source = ci_metadata["repo_uri"]
                            revision = ci_metadata.get("commit_hash")
                            logger.info(
                                f"Found CI metadata for {target_url} -> {source} (ref: {revision})"
                            )
                            # Automatically queue a Semgrep scan
                            add_repository(source)
                            create_semgrep_job(source, git_ref=revision)

            res = await asyncio.to_thread(plugin.scan, target_url, git_ref, target_type)

        # Update status to completed
        update_job_status(
            job_id,
            "completed",
            results_json=json.dumps(res.results),
            resolved_commit=res.resolved_commit or "latest",
            resolved_tags=res.resolved_tags,
        )

        logger.info(f"Job {job_id} completed successfully")

    except Exception as e:
        logger.error(f"Job {job_id} failed: {e}")
        # Update status to failed
        update_job_status(job_id, "failed", error_message=str(e))


async def process_semgrep_job(
    job_id: str, target_url: str, git_ref: str | None = None
) -> None:
    """
    Process a Semgrep SAST scan job.

    Before running the container, resolve the commit hash and check whether a
    completed Semgrep job already exists for that exact commit (full SHA-1).
    If a cache hit is found, copy the results directly; no Docker run needed.
    """
    logger.info(f"Starting semgrep job {job_id} for {target_url} at ref {git_ref}")

    try:
        # Step 1: Resolve the commit hash cheaply via ls-remote if possible,
        # but the canonical approach is to let run_semgrep_scan clone and rev-parse.
        # We delegate entirely to run_semgrep_scan which does clone → rev-parse
        # → container. However, to enable the cache check BEFORE the clone, we
        # use a lightweight git ls-remote to resolve the ref to a commit.
        import subprocess

        commit_hash: str | None = None

        # Try to resolve commit hash without a full clone using ls-remote
        try:
            import os

            from rover import vault

            ref_to_resolve = git_ref or "HEAD"
            auth_url = vault.get_authenticated_git_url(target_url)
            env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
            ls_result = subprocess.run(  # noqa: S603
                ["git", "ls-remote", auth_url, ref_to_resolve],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=15,
                env=env,
            )
            if ls_result.returncode == 0 and ls_result.stdout.strip():
                first_line = ls_result.stdout.strip().splitlines()[0]
                candidate = first_line.split()[0].strip()
                # Full SHA-1 is 40 hex chars
                if len(candidate) == 40 and all(
                    c in "0123456789abcdef" for c in candidate
                ):
                    commit_hash = candidate
        except Exception as e:
            logger.debug(f"Pre-scan ls-remote failed, will resolve after clone: {e}")

        # Step 2: Cache check; if we have the hash, look for a completed job
        if commit_hash:
            cached = get_completed_semgrep_job_by_commit(commit_hash)
            if cached:
                logger.info(
                    f"Semgrep cache HIT for commit {commit_hash[:7]} "
                    f"(existing job {cached['id']}). Reusing results."
                )
                update_semgrep_job_status(
                    job_id,
                    "completed",
                    results_json=cached["results_json"],
                    resolved_commit=cached["resolved_commit"],
                    resolved_tags=cached.get("resolved_tags"),
                )
                return

        from rover import plugins

        plugin = plugins.get_plugin_for_job("semgrep")
        res = await asyncio.to_thread(plugin.scan, target_url, git_ref, "semgrep")

        update_semgrep_job_status(
            job_id,
            "completed",
            results_json=json.dumps(res.results),
            resolved_commit=res.resolved_commit or "unknown",
            resolved_tags=res.resolved_tags,
        )
        logger.info(
            f"Semgrep job {job_id} completed (commit {res.resolved_commit[:7] if res.resolved_commit else 'unknown'})"
        )

    except Exception as e:
        logger.error(f"Semgrep job {job_id} failed: {e}")
        update_semgrep_job_status(job_id, "failed", error_message=str(e))


async def process_snyk_job(
    job_id: str, target_url: str, git_ref: str | None = None
) -> None:
    """Process a Snyk OSS & SAST scan job with commit hash caching."""
    logger.info(f"Starting snyk job {job_id} for {target_url} at ref {git_ref}")

    try:
        import subprocess

        commit_hash: str | None = None
        try:
            import os

            from rover import vault

            ref_to_resolve = git_ref or "HEAD"
            auth_url = vault.get_authenticated_git_url(target_url)
            env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
            ls_result = subprocess.run(  # noqa: S603
                ["git", "ls-remote", auth_url, ref_to_resolve],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=15,
                env=env,
            )
            if ls_result.returncode == 0 and ls_result.stdout.strip():
                first_line = ls_result.stdout.strip().splitlines()[0]
                candidate = first_line.split()[0].strip()
                if len(candidate) == 40 and all(
                    c in "0123456789abcdef" for c in candidate
                ):
                    commit_hash = candidate
        except Exception as e:
            logger.debug(f"Pre-scan ls-remote failed for snyk: {e}")

        from rover import db

        snyk_token: str | None = None
        snyk_token, _ = db.get_unmasked_secret_by_type_info(
            credential_type="snyk_token"
        )
        if not snyk_token:
            snyk_token = os.getenv("SNYK_TOKEN")

        if not snyk_token:
            raise Exception(
                "Snyk API token is not configured. Please add a Snyk Token credential in Settings -> Credentials."
            )

        if commit_hash:
            cached = get_completed_snyk_job_by_commit(commit_hash)
            if cached and cached.get("results_json"):
                try:
                    c_raw = cached["results_json"]
                    cdata = (
                        json.loads(c_raw) if isinstance(c_raw, (str, bytes)) else c_raw
                    )
                    if isinstance(cdata, dict) and (
                        "snyk_oss" in cdata or "vulnerabilities" in cdata
                    ):
                        logger.info(
                            f"Snyk cache HIT for commit {commit_hash[:7]} "
                            f"(existing job {cached['id']}). Reusing results."
                        )
                        update_snyk_job_status(
                            job_id,
                            "completed",
                            results_json=cached["results_json"],
                            resolved_commit=cached["resolved_commit"],
                            resolved_tags=cached.get("resolved_tags"),
                        )
                        return
                except Exception as cache_err:
                    logger.debug(f"Invalid cached Snyk JSON ignored: {cache_err}")

        from rover import plugins

        plugin = plugins.get_plugin_for_job("snyk")
        target_type = (
            "image"
            if not (
                target_url.startswith("http://")
                or target_url.startswith("https://")
                or target_url.startswith("git@")
            )
            else "repo"
        )
        res = await asyncio.to_thread(plugin.scan, target_url, git_ref, target_type)

        update_snyk_job_status(
            job_id,
            "completed",
            results_json=json.dumps(res.results),
            resolved_commit=res.resolved_commit or "unknown",
            resolved_tags=res.resolved_tags,
        )
        logger.info(
            f"Snyk job {job_id} completed (commit {res.resolved_commit[:7] if res.resolved_commit else 'unknown'})"
        )

    except Exception as e:
        logger.error(f"Snyk job {job_id} failed: {e}")
        update_snyk_job_status(job_id, "failed", error_message=str(e))


MAX_CONCURRENT_JOBS = 4


async def _dispatch_job(job: dict[str, Any]) -> None:
    s_name = job.get("scanner_name", "trivy")
    job_id = job["id"]
    target_url = job["target_url"]
    git_ref = job.get("git_ref")
    target_type = job.get("target_type", "repo")

    try:
        if s_name == "semgrep":
            await process_semgrep_job(job_id, target_url, git_ref)
        elif s_name == "snyk":
            await process_snyk_job(job_id, target_url, git_ref)
        else:
            await process_job(job_id, target_url, git_ref, target_type)
    except Exception as exc:
        logger.error(
            f"Error executing concurrent scanner job {job_id} ({s_name}): {exc}"
        )


async def worker_loop() -> None:
    logger.info(
        f"Starting async multi-process worker loop (max_concurrent={MAX_CONCURRENT_JOBS})"
    )
    from rover.db import claim_next_scanner_job

    active_tasks: set[asyncio.Task[None]] = set()

    while True:
        try:
            # Check and dispatch due scheduled scans
            from rover.scheduler import dispatch_due_scheduled_scans

            dispatch_due_scheduled_scans()

            # Clean up finished tasks
            active_tasks = {t for t in active_tasks if not t.done()}

            while len(active_tasks) < MAX_CONCURRENT_JOBS:
                gen_job = claim_next_scanner_job()
                if not gen_job:
                    legacy_trivy = claim_next_job()
                    if legacy_trivy:
                        gen_job = {**legacy_trivy, "scanner_name": "trivy"}
                    else:
                        legacy_semgrep = claim_next_semgrep_job()
                        if legacy_semgrep:
                            gen_job = {**legacy_semgrep, "scanner_name": "semgrep"}
                        else:
                            legacy_snyk = claim_next_snyk_job()
                            if legacy_snyk:
                                gen_job = {**legacy_snyk, "scanner_name": "snyk"}

                if not gen_job:
                    break

                task = asyncio.create_task(_dispatch_job(gen_job))
                active_tasks.add(task)

            await asyncio.sleep(1)

        except Exception as e:
            logger.error(f"Worker iteration error: {e}")
            await asyncio.sleep(2)
