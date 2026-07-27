"""tests/test_templates.py: Unit test to render all Jinja2 templates.

Ensures no Jinja2 template references missing variables, undefined functions, or deleted modules.
"""

from pathlib import Path

import pytest

from rover import db
from rover.routes._env import template_env


@pytest.fixture
def dummy_context() -> dict:
    return {
        "db": db,
        "user": {
            "sub": "user_123",
            "name": "Test User",
            "email": "test@example.com",
            "role": "system_admin",
        },
        "title": "Test Title",
        "default_tab": "repo",
        "product": {
            "id": "prod_1",
            "name": "Test Product",
            "description": "Test Description",
            "created_at": "2026-01-01 00:00:00",
        },
        "products": [
            {
                "id": "prod_1",
                "name": "Test Product",
                "description": "Test Description",
                "created_at": "2026-01-01 00:00:00",
            }
        ],
        "release": {
            "id": "rel_1",
            "product_id": "prod_1",
            "name": "v1.0.0",
            "version": "1.0.0",
            "is_end_of_life": False,
            "created_at": "2026-01-01 00:00:00",
        },
        "releases": [
            {
                "id": "rel_1",
                "product_id": "prod_1",
                "name": "v1.0.0",
                "version": "1.0.0",
                "is_end_of_life": False,
                "created_at": "2026-01-01 00:00:00",
            }
        ],
        "assets": [
            {
                "release_asset_id": "asset_1",
                "asset_type": "repo",
                "asset_id": "repo_1",
                "asset_name": "https://github.com/example/repo",
                "git_ref": "main",
                "latest_scan_id": "job_1",
                "latest_scan_status": "completed",
                "latest_scan_time": "2026-01-01 00:00:00",
                "results_json": '{"SchemaVersion": 2, "Results": []}',
                "resolved_commit": "abc1234",
                "resolved_tags": "v1.0.0",
            }
        ],
        "jobs": [
            {
                "id": "job_1",
                "target_url": "https://github.com/example/repo",
                "target_type": "repo",
                "git_ref": "main",
                "status": "completed",
                "results_json": "[]",
                "created_at": "2026-01-01 00:00:00",
                "updated_at": "2026-01-01 00:00:00",
            }
        ],
        "job": {
            "id": "job_1",
            "target_url": "https://github.com/example/repo",
            "target_type": "repo",
            "git_ref": "main",
            "status": "completed",
            "results_json": '{"SchemaVersion": 2, "Results": []}',
            "created_at": "2026-01-01 00:00:00",
            "updated_at": "2026-01-01 00:00:00",
        },
        "semgrep_job": {
            "id": "sem_1",
            "target_url": "https://github.com/example/repo",
            "status": "completed",
            "results_json": '{"results": []}',
        },
        "snyk_job": {
            "id": "snyk_1",
            "target_url": "https://github.com/example/repo",
            "status": "completed",
            "results_json": '{"vulnerabilities": []}',
        },
        "repositories": [{"id": "repo_1", "url": "https://github.com/example/repo"}],
        "images": [{"id": "img_1", "name": "example/image:latest"}],
        "major_components": [{"id": "comp_1", "name": "python", "version": "3.12"}],
        "major_component_assets": [],
        "product_role": "admin",
        "user_roles": {"user_123": "admin"},
        "all_users": [
            {
                "sub": "user_123",
                "name": "Test User",
                "email": "test@example.com",
                "role": "system_admin",
                "product_role": "admin",
            }
        ],
        "product_users": [],
        "tokens": [],
        "new_token": None,
        "config_toml": "# config",
        "back_url": "/",
        "error": None,
        "message": None,
    }


def get_all_template_names() -> list[str]:
    templates_dir = (
        Path(__file__).resolve().parent.parent / "src" / "rover" / "templates"
    )
    return [p.name for p in templates_dir.glob("*.html")]


@pytest.mark.parametrize("template_name", get_all_template_names())
def test_template_render(template_name: str, dummy_context: dict) -> None:
    """Ensure every template in src/rover/templates/ renders cleanly without undefined errors."""
    template = template_env.get_template(template_name)
    rendered = template.render(**dummy_context)
    assert isinstance(rendered, str)
    assert len(rendered) > 0


def test_no_scan_queue_in_templates() -> None:
    """Static sanity check: Ensure no template references 'scan_queue' directly."""
    templates_dir = (
        Path(__file__).resolve().parent.parent / "src" / "rover" / "templates"
    )
    for html_file in templates_dir.glob("*.html"):
        content = html_file.read_text(encoding="utf-8")
        assert "scan_queue." not in content, (
            f"Template {html_file.name} still contains references to 'scan_queue.'"
        )
