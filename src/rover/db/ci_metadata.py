import json
from typing import Any
from sqlalchemy import select, insert, update
from sqlalchemy.exc import IntegrityError
from rover.db.connection import get_db_connection
from rover.db.schema import ci_image_metadata

def add_ci_image_metadata(
    image_hash: str,
    repo_uri: str,
    commit_hash: str,
    metadata_dict: dict[str, Any],
    image_tags: list[str] = None,
    ci_job_url: str = None,
    user_sub: str = None,
    token_id: str = None
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
                    created_by_token_id=token_id
                )
            )
        return True
    except IntegrityError:
        with get_db_connection() as conn:
            row = conn.execute(
                select(ci_image_metadata.c.repo_uri, ci_image_metadata.c.commit_hash)
                .where(ci_image_metadata.c.image_hash == image_hash)
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
                        created_by_token_id=token_id
                    )
                )
                return True
        return False

def get_ci_image_metadata(image_hash: str) -> dict[str, Any] | None:
    with get_db_connection() as conn:
        row = conn.execute(
            select(ci_image_metadata).where(ci_image_metadata.c.image_hash == image_hash)
        ).fetchone()
        return dict(row._mapping) if row else None
