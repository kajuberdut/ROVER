import asyncio
import json
import logging

from rover.scan_queue import (
    claim_next_job,
    claim_next_semgrep_job,
    get_completed_semgrep_job_by_commit,
    update_job_status,
    update_semgrep_job_status,
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
        from rover import scanner

        if target_type == "major_component":
            # We expect target_url to be the name, and git_ref to be the version
            if not git_ref:
                raise ValueError(
                    "Major Component scan requires a version string in git_ref"
                )
            results, commit_hash, tags_str = await asyncio.to_thread(
                scanner.run_major_component_scan, target_url, git_ref
            )
        else:
            if target_type == "image":
                # Check for OCI annotations first
                from rover.scan_queue import (
                    add_repository,
                    create_semgrep_job,
                    get_image_by_name,
                    set_image_source,
                )

                image_record = get_image_by_name(target_url)
                if image_record and not image_record.get("source_repo_url"):
                    annotations = await asyncio.to_thread(
                        scanner.extract_oci_annotations, target_url
                    )
                    source = annotations.get("source")
                    revision = annotations.get("revision")

                    if source:
                        logger.info(
                            f"Discovered OCI annotations for {target_url} -> {source} (ref: {revision})"
                        )
                        set_image_source(image_record["id"], source, revision)
                        # Automatically queue a Semgrep scan
                        add_repository(source)
                        create_semgrep_job(source, git_ref=revision)

            # Run the actual Trivy scan using testcontainers
            # Since this is a blocking I/O operation (Docker), wrap it in to_thread so we don't
            # block the asyncio event loop while the container is running
            results, commit_hash, tags_str = await asyncio.to_thread(
                scanner.run_trivy_scan, target_url, git_ref, target_type
            )

        # Update status to completed
        update_job_status(
            job_id,
            "completed",
            results_json=json.dumps(results),
            resolved_commit=commit_hash,
            resolved_tags=tags_str,
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
    If a cache hit is found, copy the results directly — no Docker run needed.
    """
    logger.info(f"Starting semgrep job {job_id} for {target_url} at ref {git_ref}")

    try:
        # Step 1: Resolve the commit hash cheaply via ls-remote if possible,
        # but the canonical approach is to let run_semgrep_scan clone and rev-parse.
        # We delegate entirely to run_semgrep_scan which does clone → rev-parse
        # → container. However, to enable the cache check BEFORE the clone, we
        # use a lightweight git ls-remote to resolve the ref to a commit.
        import subprocess

        from rover import scanner

        commit_hash: str | None = None

        # Try to resolve commit hash without a full clone using ls-remote
        try:
            ref_to_resolve = git_ref or "HEAD"
            ls_result = subprocess.run(  # noqa: S603
                ["git", "ls-remote", target_url, ref_to_resolve],  # noqa: S607
                capture_output=True,
                text=True,
                timeout=15,
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

        # Step 2: Cache check — if we have the hash, look for a completed job
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

        # Step 3: Cache miss — run the full scan
        results, resolved_commit, tags_str = await asyncio.to_thread(
            scanner.run_semgrep_scan, target_url, git_ref
        )

        update_semgrep_job_status(
            job_id,
            "completed",
            results_json=json.dumps(results),
            resolved_commit=resolved_commit,
            resolved_tags=tags_str,
        )
        logger.info(
            f"Semgrep job {job_id} completed (commit {resolved_commit[:7] if resolved_commit else 'unknown'})"
        )

    except Exception as e:
        logger.error(f"Semgrep job {job_id} failed: {e}")
        update_semgrep_job_status(job_id, "failed", error_message=str(e))


async def worker_loop() -> None:
    logger.info("Starting background worker loop")
    while True:
        try:
            # Poll both queues each iteration
            trivy_job = claim_next_job()
            semgrep_job = claim_next_semgrep_job()

            if trivy_job:
                await process_job(
                    trivy_job["id"],
                    trivy_job["target_url"],
                    trivy_job.get("git_ref"),
                    trivy_job.get("target_type", "repo"),
                )
            if semgrep_job:
                await process_semgrep_job(
                    semgrep_job["id"],
                    semgrep_job["target_url"],
                    semgrep_job.get("git_ref"),
                )
            if not trivy_job and not semgrep_job:
                # No jobs in either queue; sleep before next poll
                await asyncio.sleep(2)

        except Exception as e:
            logger.error(f"Worker iteration error: {e}")
            await asyncio.sleep(5)
