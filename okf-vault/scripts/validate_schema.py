#!/usr/bin/env python3
"""
OKF v0.2 Frontmatter Validator Script
------------------------------------
Validates all markdown notes within the vault directory against the OKF v0.2 schema.
Checks required metadata fields: id, type, title, created, updated, tags, status, stale_after.
"""

import re
import sys
from datetime import datetime
from pathlib import Path

try:
    import yaml
except ImportError:
    print(
        "Error: PyYAML package is required for frontmatter parsing. Run: pip install pyyaml"
    )
    sys.exit(1)

VAULT_ROOT = Path(__file__).resolve().parent.parent
VALID_TYPES = {"Concept", "Resource", "Index", "Log", "Meta", "Feature"}
VALID_STATUSES = {"draft", "stable", "deprecated"}
VALID_FEATURE_STATUSES = {"completed", "in_progress", "planned", "deferred"}


def extract_frontmatter(file_path: Path) -> dict:
    content = file_path.read_text(encoding="utf-8")
    if not content.startswith("---"):
        return None

    parts = content.split("---", 2)
    if len(parts) < 3:
        return None

    try:
        data = yaml.safe_load(parts[1])
        return data if isinstance(data, dict) else None
    except Exception as e:
        print(
            f"[ERROR] Invalid YAML syntax in {file_path.relative_to(VAULT_ROOT)}: {e}"
        )
        return None


def validate_note(file_path: Path) -> list:
    errors = []
    fm = extract_frontmatter(file_path)
    rel_path = file_path.relative_to(VAULT_ROOT)

    if fm is None:
        errors.append("Missing or invalid YAML frontmatter delimiters ('---').")
        return errors

    # Check required fields
    required_fields = ["id", "type", "title", "created", "updated", "tags"]
    for field in required_fields:
        if field not in fm:
            errors.append(f"Missing required frontmatter field: '{field}'")

    # Validate 'id' (12-digit timestamp string)
    if "id" in fm:
        val = str(fm["id"])
        if not re.match(r"^\d{12}$", val):
            errors.append(
                f"Invalid 'id': '{val}'. Must be 12-digit timestamp YYYYMMDDHHMM."
            )

    # Validate 'type'
    if "type" in fm and fm["type"] not in VALID_TYPES:
        errors.append(f"Invalid 'type': '{fm['type']}'. Must be one of {VALID_TYPES}.")

    # Validate 'status' (default: stable)
    status = fm.get("status", "stable")
    if status not in VALID_STATUSES:
        errors.append(f"Invalid 'status': '{status}'. Must be one of {VALID_STATUSES}.")

    # Validate 'feature_status'
    if "feature_status" in fm and fm["feature_status"] not in VALID_FEATURE_STATUSES:
        errors.append(
            f"Invalid 'feature_status': '{fm['feature_status']}'. Must be one of {VALID_FEATURE_STATUSES}."
        )

    # Validate 'stale_after' (YYYY-MM-DD)
    if "stale_after" in fm and fm["stale_after"]:
        stale_val = str(fm["stale_after"])
        try:
            stale_date = datetime.strptime(stale_val, "%Y-%m-%d")
            if stale_date < datetime.now():
                print(
                    f"[WARNING] Note {rel_path} has expired stale_after date: {stale_val}"
                )
        except ValueError:
            errors.append(
                f"Invalid 'stale_after' date format: '{stale_val}'. Expected YYYY-MM-DD."
            )

    return errors


def main():
    print("--- OKF v0.2 Frontmatter Validation ---")
    print(f"Vault Directory: {VAULT_ROOT}\n")

    total_notes = 0
    failed_notes = 0

    # Directories containing OKF concept notes
    content_dirs = [
        VAULT_ROOT / "10_inbox",
        VAULT_ROOT / "20_concepts",
        VAULT_ROOT / "30_resources",
        VAULT_ROOT / "40_indices",
        VAULT_ROOT / "50_archive",
    ]

    for cdir in content_dirs:
        if not cdir.exists():
            continue
        for path in cdir.rglob("*.md"):
            if "00_meta/templates" in str(path) or ".git" in str(path):
                continue

            total_notes += 1
            errors = validate_note(path)
            rel_path = path.relative_to(VAULT_ROOT)

            if errors:
                failed_notes += 1
                print(f"❌ {rel_path}:")
                for err in errors:
                    print(f"   - {err}")
            else:
                print(f"✅ {rel_path}")

    print(
        f"\nValidation Summary: {total_notes - failed_notes}/{total_notes} notes passed."
    )
    if failed_notes > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
