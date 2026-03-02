import asyncio
import json
import logging

from rover.scan_queue import claim_next_job, update_job_status

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


async def process_job(job_id: str, target_url: str, git_ref: str | None = None) -> None:
    logger.info(f"Starting job {job_id} for {target_url} at ref {git_ref}")

    # Job is already set to 'running' via claim_next_job.

    try:
        from rover import scanner

        # Run the actual Trivy scan using testcontainers
        # Since this is a blocking I/O operation (Docker), wrap it in to_thread so we don't
        # block the asyncio event loop while the container is running
        results, commit_hash, tags_str = await asyncio.to_thread(
            scanner.run_trivy_scan, target_url, git_ref
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


async def worker_loop() -> None:
    logger.info("Starting background worker loop")
    while True:
        try:
            # Atomically claim the next job
            job = claim_next_job()

            if job:
                await process_job(job["id"], job["target_url"], job.get("git_ref"))
            else:
                # No jobs, sleep and poll again
                await asyncio.sleep(2)

        except Exception as e:
            logger.error(f"Worker iteration error: {e}")
            await asyncio.sleep(5)
