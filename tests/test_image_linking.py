"""tests/test_image_linking.py: Unit tests for container image source repo linking and Semgrep report integration."""

from unittest.mock import patch

from rover import db
from rover.plugins.trivy import resolve_image_hash


def test_resolve_image_hash_docker_registry_fallback() -> None:
    # Skopeo fails, Docker registry succeeds
    with patch("subprocess.run", side_effect=Exception("Skopeo missing")):
        digest = resolve_image_hash("jellyfin/jellyfin:latest")
        assert digest is not None
        assert digest.startswith("sha256:")


def test_image_link_repo_and_report_integration() -> None:
    # 1. Create product, release, image
    product_id = db.add_product("Image Link Test Product", "Test Desc")
    release_id = db.add_release(product_id, "v1.0.0", "1.0.0")
    image_id = db.add_image("jellyfin/jellyfin")
    db.add_release_asset(release_id, "image", image_id)

    # 2. Add CI metadata linking image to source repo
    image = db.get_image(image_id)
    image_hash = image.get("image_hash") or f"image_name:{image['name']}"
    db.update_image_hash(image_id, image_hash)

    source_url = "https://github.com/jellyfin/jellyfin"
    commit = "master"
    db.add_ci_image_metadata(
        image_hash=image_hash,
        repo_uri=source_url,
        commit_hash=commit,
        metadata_dict={"source": "manual_link"},
    )
    db.add_repository(source_url)
    db.create_semgrep_job(source_url, git_ref=commit)

    # 3. Verify get_release_assets_with_latest_scans includes source_repo_url and image_source_git_ref
    assets = db.get_release_assets_with_latest_scans(release_id)
    assert len(assets) == 1
    found = assets[0]
    assert found["source_repo_url"] == source_url
    assert found["image_source_git_ref"] == commit

    # 4. Verify report resource retrieves semgrep_job for image scans
    db.create_job("jellyfin/jellyfin", target_type="image")
    semgrep_job = db.get_semgrep_job_for_target(source_url, commit)

    assert semgrep_job is not None
    assert semgrep_job["target_url"] == source_url
