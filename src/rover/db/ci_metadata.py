import json
from typing import Any

from sqlalchemy import insert, select, update
from sqlalchemy.exc import IntegrityError

from rover.db.connection import get_db_connection
from rover.db.schema import ci_image_metadata


def add_ci_image_metadata(
    image_hash: str,
    repo_uri: str,
    commit_hash: str,
    metadata_dict: dict[str, Any],
    image_tags: list[str] | None = None,
    ci_job_url: str | None = None,
    user_sub: str | None = None,
    token_id: str | None = None,
) -> bool:

    metadata_json = json.dumps(metadata_dict)
    tags_json = json.dumps(image_tags or [])

    try:
        with get_db_connection() as conn:
            conn.execute(
                insert(ci_image_metadata).values(
                    image_hash=image_hash,
                    repo_uri=repo_uri,
                    commit_hash=commit_hash,
                    metadata_json=metadata_json,
                    image_tags=tags_json,
                    ci_job_url=ci_job_url,
                    created_by_user_sub=user_sub,
                    created_by_token_id=token_id,
                )
            )
        return True
    except IntegrityError:
        with get_db_connection() as conn:
            row = conn.execute(
                select(
                    ci_image_metadata.c.repo_uri, ci_image_metadata.c.commit_hash
                ).where(ci_image_metadata.c.image_hash == image_hash)
            ).fetchone()

            if row and row.repo_uri == repo_uri and row.commit_hash == commit_hash:
                conn.execute(
                    update(ci_image_metadata)
                    .where(ci_image_metadata.c.image_hash == image_hash)
                    .values(
                        metadata_json=metadata_json,
                        image_tags=tags_json,
                        ci_job_url=ci_job_url,
                        created_by_user_sub=user_sub,
                        created_by_token_id=token_id,
                    )
                )
                return True
        return False


def get_ci_image_metadata(image_hash: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(ci_image_metadata).where(
                ci_image_metadata.c.image_hash == image_hash
            )
        ).fetchone()
        return dict(row._mapping) if row else None


def get_linked_targets(target_url: str) -> dict[str, Any]:
    """Given either an image name or a repo URL, return linked target details."""
    from sqlalchemy import text

    with get_db_connection() as conn:
        # Check if target_url is an image name
        row = (
            conn.execute(
                text("""
            SELECT i.name as image_name, cim.repo_uri as source_repo_url, cim.commit_hash as source_git_ref
            FROM images i
            JOIN ci_image_metadata cim ON i.image_hash = cim.image_hash
            WHERE i.name = :target_url
            """),
                {"target_url": target_url},
            )
            .mappings()
            .first()
        )
        if row:
            return dict(row)

        # Check if target_url is a repo URI
        row = (
            conn.execute(
                text("""
            SELECT i.name as image_name, cim.repo_uri as source_repo_url, cim.commit_hash as source_git_ref
            FROM ci_image_metadata cim
            JOIN images i ON cim.image_hash = i.image_hash
            WHERE cim.repo_uri = :target_url
            """),
                {"target_url": target_url},
            )
            .mappings()
            .first()
        )
        if row:
            return dict(row)

        return {"image_name": None, "source_repo_url": None, "source_git_ref": None}
