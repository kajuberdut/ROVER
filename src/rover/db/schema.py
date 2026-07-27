from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    Column,
    ForeignKey,
    Index,
    MetaData,
    String,
    Table,
    text,
)
from sqlalchemy.sql import func

metadata = MetaData()

scan_jobs = Table(
    "scan_jobs",
    metadata,
    Column("id", String, primary_key=True),
    Column("target_url", String, nullable=False),
    Column("git_ref", String, default=None),
    Column("status", String, nullable=False),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("updated_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("results_json", String, default=None),
    Column("error_message", String, default=None),
    Column("resolved_commit", String, default=None),
    Column("resolved_tags", String, default=None),
    Column("target_type", String, server_default="repo"),
)

repositories = Table(
    "repositories",
    metadata,
    Column("id", String, primary_key=True),
    Column("url", String, unique=True, nullable=False),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
)

images = Table(
    "images",
    metadata,
    Column("id", String, primary_key=True),
    Column("name", String, unique=True, nullable=False),
    Column("image_hash", String, default=None),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
)

major_components = Table(
    "major_components",
    metadata,
    Column("id", String, primary_key=True),
    Column("name", String, nullable=False),
    Column("version", String, nullable=False),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Index("sqlite_autoindex_major_components_1", "name", "version", unique=True),
)

eol_cache = Table(
    "eol_cache",
    metadata,
    Column("id", String, primary_key=True),
    Column("name", String, nullable=False),
    Column("version", String, nullable=False),
    Column("response_json", String, nullable=False),
    Column("cached_at", TIMESTAMP, server_default=func.current_timestamp()),
)

products = Table(
    "products",
    metadata,
    Column("id", String, primary_key=True),
    Column("name", String, unique=True, nullable=False),
    Column("description", String, server_default=""),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
)

releases = Table(
    "releases",
    metadata,
    Column("id", String, primary_key=True),
    Column("product_id", String),
    Column("name", String, nullable=False),
    Column("version", String, nullable=False),
    Column("is_end_of_life", Boolean, server_default=text("false")),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
)

release_assets = Table(
    "release_assets",
    metadata,
    Column("id", String, primary_key=True),
    Column("release_id", String, ForeignKey("releases.id"), nullable=False),
    Column("asset_type", String, nullable=False),
    Column("asset_id", String, nullable=False),
    Column("git_ref", String, default=None),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
)

# Index idx_rel_asset_unique from init_db using coalesce for git_ref compatibility (will fix manually if needed later)
# Actually, SQLAlchemy allows creating indexes with expressions, but for now we'll define a basic index or just let the SQLite init handle it in phase 1.

semgrep_jobs = Table(
    "semgrep_jobs",
    metadata,
    Column("id", String, primary_key=True),
    Column("target_url", String, nullable=False),
    Column("git_ref", String, default=None),
    Column("resolved_commit", String, default=None),
    Column("status", String, nullable=False),
    Column("results_json", String, default=None),
    Column("resolved_tags", String, default=None),
    Column("error_message", String, default=None),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("updated_at", TIMESTAMP, server_default=func.current_timestamp()),
)

snyk_jobs = Table(
    "snyk_jobs",
    metadata,
    Column("id", String, primary_key=True),
    Column("target_url", String, nullable=False),
    Column("git_ref", String, default=None),
    Column("resolved_commit", String, default=None),
    Column("status", String, nullable=False),
    Column("results_json", String, default=None),
    Column("resolved_tags", String, default=None),
    Column("error_message", String, default=None),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("updated_at", TIMESTAMP, server_default=func.current_timestamp()),
)

users = Table(
    "users",
    metadata,
    Column("sub", String, primary_key=True),
    Column("email", String),
    Column("name", String),
    Column("role", String, nullable=False, server_default="viewer"),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("last_login", TIMESTAMP),
)

product_users = Table(
    "product_users",
    metadata,
    Column(
        "user_sub",
        String,
        ForeignKey("users.sub", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    ),
    Column(
        "product_id",
        String,
        ForeignKey("products.id", ondelete="CASCADE"),
        primary_key=True,
        nullable=False,
    ),
    Column("role", String, nullable=False),
)

api_tokens = Table(
    "api_tokens",
    metadata,
    Column("id", String, primary_key=True),
    Column(
        "user_sub", String, ForeignKey("users.sub", ondelete="CASCADE"), nullable=False
    ),
    Column("name", String, nullable=False),
    Column("token_hash", String, unique=True, nullable=False),
    Column("permission", String, nullable=False),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("last_used_at", TIMESTAMP),
)

ci_image_metadata = Table(
    "ci_image_metadata",
    metadata,
    Column("image_hash", String, primary_key=True),
    Column("repo_uri", String, nullable=False),
    Column("commit_hash", String, nullable=False),
    Column("metadata_json", String, server_default="{}"),
    Column("image_tags", String, server_default="[]"),
    Column("ci_job_url", String, default=None),
    Column("created_by_user_sub", String, default=None),
    Column("created_by_token_id", String, default=None),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
)

admin_notifications = Table(
    "admin_notifications",
    metadata,
    Column("id", String, primary_key=True),
    Column("title", String, nullable=False),
    Column("message", String, nullable=False),
    Column("category", String, nullable=False, server_default="scanner_update"),
    Column("source_tool", String, nullable=False),
    Column("metadata_json", String, server_default="{}"),
    Column("is_dismissed", Boolean, server_default=text("false")),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("dismissed_at", TIMESTAMP, default=None),
)

credentials = Table(
    "credentials",
    metadata,
    Column("id", String, primary_key=True),
    Column("name", String, nullable=False),
    Column("type", String, nullable=False),
    Column("scope", String, nullable=False),
    Column(
        "product_id",
        String,
        ForeignKey("products.id", ondelete="CASCADE"),
        default=None,
    ),
    Column("description", String, default=None),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("updated_at", TIMESTAMP, server_default=func.current_timestamp()),
)
