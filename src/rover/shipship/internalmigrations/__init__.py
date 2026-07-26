"""
Manage shipship's internal table structure.
"""

from datetime import datetime, timezone

from . import v1

#: Mapping of {schema version number: module}
#: Version 0: no migration tables exist (fresh database).
#: Version 1: current schema; all shipship tracking tables present.
schema_versions = {0: None, 1: v1}

#: First schema version that uses the version tracking table.
USE_VERSION_TABLE_FROM = 1


def needs_upgrading(backend):
    return get_current_version(backend) < max(schema_versions)


def upgrade(backend, version=None):
    """
    Check the currently installed shipship schema version and upgrade if needed.
    """
    desired_version = version if version is not None else max(schema_versions)
    current_version = get_current_version(backend)
    with backend.transaction():
        while current_version < desired_version:
            next_version = current_version + 1
            module = schema_versions[next_version]
            if module is not None:
                module.upgrade(backend)
            current_version = next_version
            mark_schema_version(backend, current_version)


def get_current_version(backend):
    """
    Return the currently installed shipship schema version.

    Returns 0 if no tables exist yet (fresh database), or if the tables
    are in an unexpected partial state.
    """
    tables = set(backend.list_tables())
    version_table = backend.version_table
    if backend.migration_table not in tables:
        return 0
    if version_table not in tables:
        # Unexpected state (migration table without version table).
        # Treat as uninitialised to trigger a clean re-init.
        return 0
    qi = backend.quote_identifier
    cursor = backend.execute(f"SELECT max({qi('version')}) FROM {qi(version_table)}")
    version = cursor.fetchone()[0]
    if version is None or version not in schema_versions:
        return 0
    return version


def mark_schema_version(backend, version):
    """Mark the given schema version as installed."""
    assert version in schema_versions
    if version < USE_VERSION_TABLE_FROM:
        return
    backend.execute(
        f"INSERT INTO {backend.version_table_quoted} VALUES (:version, :when)",
        {"version": version, "when": datetime.now(timezone.utc).replace(tzinfo=None)},
    )
