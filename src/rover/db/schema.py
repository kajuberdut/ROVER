from sqlalchemy import (
    TIMESTAMP,
    Boolean,
    Column,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    text,
)
from sqlalchemy.sql import func

metadata = MetaData()

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
    Index("idx_major_components_name_version", "name", "version", unique=True),
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

scanner_jobs = Table(
    "scanner_jobs",
    metadata,
    Column("id", String, primary_key=True),
    Column("scanner_name", String, nullable=False),
    Column("asset_id", String, default=None),
    Column("target_url", String, nullable=False),
    Column("target_type", String, server_default="repo"),
    Column("git_ref", String, default=None),
    Column("product_id", String, default=None),
    Column("credential_id", String, default=None),
    Column("status", String, nullable=False, server_default="queued"),
    Column("results_json", String, default=None),
    Column("error_message", String, default=None),
    Column("resolved_commit", String, default=None),
    Column("resolved_tags", String, default=None),
    Column("started_at", TIMESTAMP, default=None),
    Column("finished_at", TIMESTAMP, default=None),
    Column("duration_seconds", Integer, default=None),
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
    Column("is_verified", Boolean, nullable=False, server_default=text("false")),
    Column("password_hash", String, default=None),
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

scheduled_scans = Table(
    "scheduled_scans",
    metadata,
    Column("id", String, primary_key=True),
    Column("name", String, nullable=False),
    Column(
        "product_id",
        String,
        ForeignKey("products.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("release_id", String, ForeignKey("releases.id", ondelete="CASCADE")),
    Column("cron_expression", String, nullable=False, server_default="0 2 * * *"),
    Column("enabled", Boolean, nullable=False, server_default="true"),
    Column("last_run_at", TIMESTAMP),
    Column("next_run_at", TIMESTAMP),
    Column("last_status", String, server_default="idle"),
    Column("created_by_user_sub", String),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("updated_at", TIMESTAMP, server_default=func.current_timestamp()),
)

schedule_execution_logs = Table(
    "schedule_execution_logs",
    metadata,
    Column("id", String, primary_key=True),
    Column(
        "schedule_id",
        String,
        ForeignKey("scheduled_scans.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("triggered_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("status", String, nullable=False),
    Column("jobs_created_count", Integer, server_default="0"),
    Column("details_json", String),
    Column("error_message", String),
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

notification_destinations = Table(
    "notification_destinations",
    metadata,
    Column("id", String, primary_key=True),
    Column("name", String, nullable=False),
    Column("type", String, nullable=False),
    Column("scope", String, nullable=False),
    Column(
        "user_sub",
        String,
        ForeignKey("users.sub", ondelete="CASCADE"),
        default=None,
    ),
    Column(
        "product_id",
        String,
        ForeignKey("products.id", ondelete="CASCADE"),
        default=None,
    ),
    Column("is_system", Boolean, nullable=False, server_default="false"),
    Column("is_default", Boolean, nullable=False, server_default="false"),
    Column("is_verified", Boolean, nullable=False, server_default=text("false")),
    Column("config_json", String, nullable=False, server_default="{}"),
    Column("vault_secret_path", String, default=None),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("updated_at", TIMESTAMP, server_default=func.current_timestamp()),
)

notification_rules = Table(
    "notification_rules",
    metadata,
    Column("id", String, primary_key=True),
    Column(
        "destination_id",
        String,
        ForeignKey("notification_destinations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("event_type", String, nullable=False),
    Column("min_severity", String, nullable=False, server_default="ALL"),
    Column("eol_warning_days", Integer, default=None),
    Column("scope", String, nullable=False),
    Column(
        "user_sub",
        String,
        ForeignKey("users.sub", ondelete="CASCADE"),
        default=None,
    ),
    Column(
        "product_id",
        String,
        ForeignKey("products.id", ondelete="CASCADE"),
        default=None,
    ),
    Column("is_enabled", Boolean, nullable=False, server_default="true"),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
    Column("updated_at", TIMESTAMP, server_default=func.current_timestamp()),
)

notification_logs = Table(
    "notification_logs",
    metadata,
    Column("id", String, primary_key=True),
    Column(
        "rule_id",
        String,
        ForeignKey("notification_rules.id", ondelete="SET NULL"),
        default=None,
    ),
    Column(
        "destination_id",
        String,
        ForeignKey("notification_destinations.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("event_type", String, nullable=False),
    Column("status", String, nullable=False),
    Column("http_status_code", Integer, default=None),
    Column("error_message", String, default=None),
    Column("payload_json", String, default=None),
    Column("retry_count", Integer, server_default="0"),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
)

notification_rule_recipients = Table(
    "notification_rule_recipients",
    metadata,
    Column("id", String, primary_key=True),
    Column(
        "rule_id",
        String,
        ForeignKey("notification_rules.id", ondelete="CASCADE"),
        nullable=False,
    ),
    Column("recipient_type", String, nullable=False, server_default="user"),
    Column(
        "user_sub",
        String,
        ForeignKey("users.sub", ondelete="CASCADE"),
        default=None,
    ),
    Column("email", String, default=None),
    Column("created_at", TIMESTAMP, server_default=func.current_timestamp()),
)

user_invites = Table(
    "user_invites",
    metadata,
    Column("id", String, primary_key=True),
    Column("email", String, nullable=True),
    Column("role", String, nullable=False, server_default="viewer"),
    Column("token", String, nullable=False, unique=True, index=True),
    Column(
        "invited_by_sub",
        String,
        ForeignKey("users.sub", ondelete="SET NULL"),
        nullable=True,
    ),
    Column("status", String, nullable=False, server_default="pending", index=True),
    Column("expires_at", TIMESTAMP(timezone=True), nullable=False),
    Column(
        "created_at", TIMESTAMP(timezone=True), server_default=func.current_timestamp()
    ),
    Column("accepted_at", TIMESTAMP(timezone=True), nullable=True),
    Column(
        "accepted_by_sub",
        String,
        ForeignKey("users.sub", ondelete="SET NULL"),
        nullable=True,
    ),
)
