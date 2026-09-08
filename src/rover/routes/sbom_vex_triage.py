"""src/rover/routes/sbom_vex_triage.py — API routes for SBOM export, VEX statement delivery, and human vulnerability triage."""

import logging
from typing import Any

import falcon
import falcon.asgi

from rover import db, permissions, vex
from rover.db.types import FindingStatus, VexJustification, VexSpecType

logger = logging.getLogger(__name__)


class ReleaseSbomResource:
    """GET /api/releases/{id}/sbom — Exports consolidated CycloneDX or SPDX SBOM document."""

    @falcon.before(permissions.require_product_read)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        fmt = req.get_param("format", default="cyclonedx").lower()
        if fmt not in ("cyclonedx", "spdx"):
            raise falcon.HTTPBadRequest(
                description="Invalid format. Supported formats: 'cyclonedx', 'spdx'"
            )

        release = db.get_release(release_id)
        if not release:
            raise falcon.HTTPNotFound(description="Release not found")

        assets = db.get_release_assets_with_latest_scans(release_id)
        all_components: list[dict[str, Any]] = []

        for asset in assets:
            a_id = asset.get("release_asset_id") or asset.get("id")
            if a_id:
                comps = db.list_sbom_components(release_asset_id=a_id)
                all_components.extend(comps)

        if fmt == "cyclonedx":
            payload = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.6",
                "version": 1,
                "components": [
                    {
                        "name": c["name"],
                        "version": c["version"],
                        "purl": c.get("purl"),
                        "cpe": c.get("cpe"),
                        "type": c.get("component_type", "library"),
                        "licenses": [{"license": {"id": c["license_spdx"]}}]
                        if c.get("license_spdx")
                        else [],
                    }
                    for c in all_components
                ],
            }
        else:
            payload = {
                "spdxVersion": "SPDX-2.3",
                "dataLicense": "CC0-1.0",
                "name": f"ROVER Release SBOM - {release.get('name', release_id)}",
                "packages": [
                    {
                        "name": c["name"],
                        "versionInfo": c["version"],
                        "licenseConcluded": c.get("license_spdx") or "NOASSERTION",
                        "externalRefs": [
                            {"referenceType": "purl", "referenceLocator": c["purl"]}
                        ]
                        if c.get("purl")
                        else [],
                    }
                    for c in all_components
                ],
            }

        resp.status = falcon.HTTP_200
        resp.media = payload


class ReleaseVexResource:
    """GET /api/releases/{id}/vex.json — Exports machine-readable OpenVEX or CycloneDX VEX document."""

    @falcon.before(permissions.require_product_read)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, release_id: str
    ) -> None:
        fmt = req.get_param("format", default="openvex").lower()
        release = db.get_release(release_id)
        if not release:
            raise falcon.HTTPNotFound(description="Release not found")

        if fmt == "cyclonedx":
            doc = vex.generate_cyclonedx_vex_document(release_id)
        else:
            doc = vex.generate_openvex_document(release_id)

        resp.status = falcon.HTTP_200
        resp.media = doc


class VulnerabilityTriageResource:
    """POST /api/vulnerabilities/{id}/triage — Submits human triage decision or proposal for approval."""

    @falcon.before(permissions.require_product_read_write)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, vuln_id: str
    ) -> None:
        try:
            data = await req.get_media()
        except Exception:
            raise falcon.HTTPBadRequest(description="Invalid JSON payload")

        if not isinstance(data, dict):
            raise falcon.HTTPBadRequest(description="Payload must be a JSON object")

        status = data.get("status")
        justification = data.get(
            "justification", VexJustification.VULNERABLE_CODE_NOT_PRESENT.value
        )
        impact_statement = data.get("impact_statement", "")
        expires_at = data.get("expires_at")

        valid_statuses = {s.value for s in FindingStatus}
        if not status or status not in valid_statuses:
            raise falcon.HTTPBadRequest(
                description=f"Invalid status. Must be one of: {', '.join(sorted(valid_statuses))}"
            )

        if not impact_statement:
            raise falcon.HTTPBadRequest(
                description="Mandatory impact_statement narrative is required for triage."
            )

        release_asset_id = data.get("release_asset_id")
        package_name = data.get("package_name", "unknown")
        installed_version = data.get("installed_version", "unknown")

        ledger_id = db.resolve_vulnerability_ledger_id(
            vuln_id,
            release_asset_id=release_asset_id,
            package_name=package_name,
            installed_version=installed_version,
        )
        if not ledger_id:
            raise falcon.HTTPNotFound(
                description=f"Vulnerability '{vuln_id}' not found in asset vulnerability ledger and could not be resolved."
            )

        user = getattr(req.context, "user", {}) or {}
        user_sub = user.get("sub", "system")

        triage_id = db.add_triage_decision(
            vulnerability_ledger_id=ledger_id,
            user_sub=user_sub,
            status=status,
            justification=justification,
            impact_statement=impact_statement,
            expires_at=expires_at,
            is_approved=False,
        )

        try:
            vuln_name = data.get("vulnerability_id", vuln_id)
            user_email = user.get("email", user_sub)
            prev_vex = db.get_product_vex_history(
                vuln_name, release_asset_id=release_asset_id
            )
            is_ext = prev_vex is not None
            orig_pkg = (
                f"{prev_vex.get('package_name')} v{prev_vex.get('installed_version')}"
                if prev_vex
                else None
            )
            target_pkg = f"{package_name} v{installed_version}"

            if is_ext:
                title = f"VEX Triage Approval Needed (Extension): {vuln_name} ({target_pkg})"
                message = (
                    f"User '{user_email}' submitted a request to extend an existing Product VEX to {target_pkg}.\n"
                    f"Originally triaged on {orig_pkg}.\n"
                    f"Justification: {justification}\n"
                    f"Impact Narrative: {impact_statement}"
                )
            else:
                title = f"VEX Triage Approval Needed: {vuln_name}"
                message = (
                    f"User '{user_email}' submitted a VEX triage request for {vuln_name} ({status}).\n"
                    f"Justification: {justification}\n"
                    f"Impact Narrative: {impact_statement}"
                )

            meta = {
                "triage_id": triage_id,
                "vulnerability_ledger_id": ledger_id,
                "requested_by": user_email,
                "requested_expiration": expires_at or "30 days",
                "is_extension": is_ext,
                "original_package": orig_pkg,
                "target_package": target_pkg,
            }

            db.create_admin_notification(
                title=title,
                message=message,
                category="vex_triage_approval",
                source_tool="vex_engine",
                metadata_dict=meta,
            )
        except (KeyError, ValueError, RuntimeError, TypeError) as e:
            # Catch notification metadata construction or payload errors so they do not block the HTTP proposal
            logger.warning(f"Failed to dispatch triage approval notification: {e}")

        resp.status = falcon.HTTP_201
        resp.media = {
            "message": "VEX triage proposal submitted for System Admin approval.",
            "triage_id": triage_id,
            "status": status,
            "triage_state": "pending_approval",
        }


class TriageApproveResource:
    """POST /api/triage/{id}/approve — Approves a pending VEX triage proposal."""

    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, triage_id: str
    ) -> None:
        user = getattr(req.context, "user", {}) or {}
        admin_sub = user.get("sub", "admin")

        triage_rec = db.get_triage_decision(triage_id)
        if not triage_rec:
            raise falcon.HTTPNotFound(description="Triage decision not found")

        override_expires_at = None
        if req.content_length:
            try:
                body = await req.get_media()
                if isinstance(body, dict):
                    override_expires_at = body.get("expires_at") or body.get(
                        "expiration_interval"
                    )
            except Exception as e:
                logger.debug(f"Could not parse approval body payload: {e}")
        if not override_expires_at:
            override_expires_at = req.get_param("expires_at")

        success = db.approve_triage_decision(
            triage_id, admin_sub, expires_at=override_expires_at
        )
        if not success:
            raise falcon.HTTPBadRequest(description="Failed to approve triage decision")

        vuln_id_val = (
            triage_rec.get("vulnerability_id")
            or triage_rec.get("vulnerability_ledger_id")
            or "CVE-UNKNOWN"
        )
        pkg_name = triage_rec.get("package_name") or "rover-asset"
        pkg_ver = triage_rec.get("installed_version") or "1.0"
        product_purl = f"pkg:generic/{pkg_name}@{pkg_ver}"

        vex.create_and_save_vex_statement(
            triage_id=triage_id,
            vulnerability_id=vuln_id_val,
            product_purl=product_purl,
            status=triage_rec["status"],
            justification=triage_rec["justification"],
            impact_statement=triage_rec["impact_statement"],
            spec_type=VexSpecType.OPENVEX.value,
        )

        resp.status = falcon.HTTP_200
        resp.media = {
            "message": "Triage proposal approved and activated.",
            "triage_id": triage_id,
            "triage_state": "active",
        }


class TriageRejectResource:
    """POST /api/triage/{id}/reject — Rejects a pending VEX triage proposal."""

    @falcon.before(permissions.require_system_admin)
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, triage_id: str
    ) -> None:
        user = getattr(req.context, "user", {}) or {}
        admin_sub = user.get("sub", "admin")

        success = db.reject_triage_decision(triage_id, admin_sub)
        if not success:
            raise falcon.HTTPNotFound(description="Triage decision not found")

        resp.status = falcon.HTTP_200
        resp.media = {
            "message": "Triage proposal rejected.",
            "triage_id": triage_id,
            "triage_state": "rejected",
        }


class TriageRevokeResource:
    """DELETE /api/triage/{id} — Revokes an active triage disposition."""

    @falcon.before(permissions.require_system_admin)
    async def on_delete(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, triage_id: str
    ) -> None:
        success = db.revoke_triage_decision(triage_id)
        if not success:
            raise falcon.HTTPNotFound(description="Triage decision not found")

        resp.status = falcon.HTTP_200
        resp.media = {"message": "Triage decision revoked successfully."}


class ProductVexLookupResource:
    """GET /api/vulnerabilities/{vuln_id}/product_vex — Retrieves historical product-level VEX decision for a CVE."""

    @falcon.before(permissions.require_product_read)
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, vuln_id: str
    ) -> None:
        release_asset_id = req.get_param("release_asset_id")
        product_id = req.get_param("product_id")

        p_vex = db.get_product_vex_history(
            vulnerability_id=vuln_id,
            release_asset_id=release_asset_id,
            product_id=product_id,
        )

        resp.status = falcon.HTTP_200
        if p_vex:
            resp.media = {"found": True, "product_vex": p_vex}
        else:
            resp.media = {"found": False, "product_vex": None}
