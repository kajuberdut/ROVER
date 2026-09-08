"""tests/test_trivy_phase2.py — Unit tests for Phase 2 Trivy Scanner Plugin refactoring (VEX flag injection & SBOM ingestion)."""

import json
from unittest.mock import MagicMock

import pytest
from sqlalchemy import create_engine

from rover import db
from rover.db import connection, schema
from rover.plugins.trivy import (
    TrivyScannerPlugin,
    parse_cyclonedx_components,
    parse_spdx_components,
)


@pytest.fixture(autouse=True)
def setup_test_db():
    """Sets up an in-memory SQLite database for testing."""
    test_engine = create_engine("sqlite:///:memory:")
    connection.engine = test_engine
    schema.metadata.create_all(test_engine)
    yield test_engine


def test_parse_cyclonedx_components():
    """Tests parsing a CycloneDX JSON document into component dicts."""
    cdx_data = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "components": [
            {
                "name": "openssl",
                "version": "3.0.8",
                "purl": "pkg:apk/alpine/openssl@3.0.8",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
                "type": "library",
            },
            {
                "name": "curl",
                "version": "8.0.1",
                "licenses": [{"expression": "MIT"}],
                "type": "application",
            },
        ],
    }
    comps = parse_cyclonedx_components(json.dumps(cdx_data))
    assert len(comps) == 2
    assert comps[0]["name"] == "openssl"
    assert comps[0]["license_spdx"] == "Apache-2.0"
    assert comps[1]["name"] == "curl"
    assert comps[1]["license_spdx"] == "MIT"


def test_parse_spdx_components():
    """Tests parsing an SPDX JSON document into component dicts."""
    spdx_data = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "urllib3",
                "versionInfo": "1.26.5",
                "licenseConcluded": "MIT",
                "externalRefs": [
                    {
                        "referenceType": "purl",
                        "referenceLocator": "pkg:pypi/urllib3@1.26.5",
                    }
                ],
            }
        ],
    }
    comps = parse_spdx_components(json.dumps(spdx_data))
    assert len(comps) == 1
    assert comps[0]["name"] == "urllib3"
    assert comps[0]["license_spdx"] == "MIT"
    assert comps[0]["purl"] == "pkg:pypi/urllib3@1.26.5"


def test_trivy_scan_vex_and_db_ingestion():
    """Tests TrivyScannerPlugin.scan with vex_path and release_asset_id finding/SBOM ingestion."""
    plugin = TrivyScannerPlugin()

    # Seed product, release, asset
    prod_id = db.add_product("Phase2 Product", "P2 Desc")
    rel_id = db.add_release(prod_id, "v1.0.0", "Release 1")
    img_id = db.add_image("nginx:latest")
    asset_id = db.add_release_asset(rel_id, "image", img_id)

    mock_stdout = json.dumps(
        {
            "Results": [
                {
                    "Target": "nginx:latest",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2024-5555",
                            "PkgName": "libssl3",
                            "InstalledVersion": "3.0.2",
                            "FixedVersion": "3.0.8",
                            "Severity": "HIGH",
                        }
                    ],
                    "Packages": [
                        {
                            "Name": "libssl3",
                            "Version": "3.0.2",
                            "Licenses": ["OpenSSL"],
                        }
                    ],
                }
            ]
        }
    ).encode("utf-8")

    mock_container = MagicMock()
    mock_container.get_logs.return_value = (mock_stdout, b"")
    mock_container.get_docker_client.return_value.client.containers.get.return_value.wait.return_value = {
        "StatusCode": 0
    }
    mock_container_cls = MagicMock(return_value=mock_container)

    mock_runner = MagicMock()
    mock_runner.return_value.stdout = "abc123commit\n"

    result = plugin.scan(
        target_url="nginx:latest",
        git_ref="v1.0.0",
        target_type="image",
        container_cls=mock_container_cls,
        subprocess_runner=mock_runner,
        vex_path="/tmp/vendor.vex.json",
        release_asset_id=asset_id,
    )

    # Verify container command includes --vex flag
    mock_container.with_command.assert_called_with(
        "image nginx:latest --vex /tmp/vendor.vex.json -f json"
    )

    # Verify ScanResult SBOM fields
    assert result.sbom_format == "cyclonedx"
    assert result.sbom_payload is not None
    assert len(result.sbom_components) == 1
    assert result.sbom_components[0]["name"] == "libssl3"

    # Verify DB ingestion of vulnerabilities
    vulns = db.list_asset_vulnerabilities(release_asset_id=asset_id)
    assert len(vulns) == 1
    assert vulns[0]["vulnerability_id"] == "CVE-2024-5555"
    assert vulns[0]["severity"] == "HIGH"

    # Verify DB ingestion of SBOM
    sbom_rec = db.get_sbom_for_asset(asset_id)
    assert sbom_rec is not None
    assert sbom_rec["format"] == "cyclonedx"
