"""rover/routes/__init__.py: Falcon ASGI application factory.

This is the only module that calls ``app.add_route()``. All resource
classes are imported from their domain modules; route registration is
centralised here so the full route table is visible in one place.
"""

import os

import falcon
import falcon.asgi

from rover import auth
from rover.eol_proxy import EolProxyAllResource, EolProxyProductResource
from rover.routes.admin import (
    AdminAlertsResource,
    AdminDestinationsResource,
    AdminInvitesCreateResource,
    AdminInvitesResendResource,
    AdminInvitesRevokeResource,
    AdminRedirectResource,
    AdminUsersResource,
    ConfigResource,
)
from rover.routes.api import CiImageMetadataResource
from rover.routes.assets import (
    ImageResource,
    MajorComponentResource,
    ReleaseAssetDetailResource,
    ReleaseAssetResource,
    ReleaseAssetsTableResource,
    ReleaseMajorComponentCardsResource,
    RepositoryResource,
)
from rover.routes.credentials import (
    AdminCredentialDeleteResource,
    AdminCredentialsResource,
)
from rover.routes.dashboard import (
    DashboardResource,
    FaviconResource,
    QueueTableResource,
)
from rover.routes.helm import HelmRepoChartsResource, ReleaseHelmResource
from rover.routes.invites import AcceptInviteResource
from rover.routes.products import (
    ProductDashboardResource,
    ProductDeleteResource,
    ProductPermissionsResource,
    ProductResource,
)
from rover.routes.refs import (
    ImageLinkRepoResource,
    ImageRefsResource,
    RemoteImageRefsResource,
    RemoteRepoRefsResource,
    RepoRefsResource,
)
from rover.routes.releases import (
    ReleaseDashboardResource,
    ReleaseDeleteResource,
    ReleaseEolResource,
    ReleaseResource,
    ReleaseScanResource,
)
from rover.routes.reports import ReportResource, ScanResource
from rover.routes.settings import (
    ApiTokenCreateResource,
    ApiTokenPageResource,
    ApiTokenRevokeResource,
)


def create_app() -> falcon.asgi.App:
    """Create and return the configured Falcon ASGI application."""
    app = falcon.asgi.App(middleware=[auth.RequireAuthMiddleware()])

    # Static files
    static_path = os.path.join(os.path.dirname(__file__), "..", "static")
    app.add_static_route("/static", static_path)

    starlight_dist = os.path.abspath(
        os.path.join(
            os.path.dirname(__file__), "..", "..", "..", "docs", "starlight", "dist"
        )
    )
    if os.path.exists(starlight_dist):
        from rover.routes.api import StarlightDocsResource

        starlight_resource = StarlightDocsResource(starlight_dist)
        app.add_route("/docs/guide", starlight_resource)
        app.add_route("/docs/guide/{filepath:path}", starlight_resource)

    # Auth routes (handled by rover.auth)
    app.add_route("/login", auth.LoginResource())
    app.add_route("/callback", auth.CallbackResource())
    app.add_route("/logout", auth.LogoutResource())

    # EOL proxy routes (handled by rover.eol_proxy)
    app.add_route("/api/eol/all", EolProxyAllResource())
    app.add_route("/api/eol/{product}", EolProxyProductResource())

    # Dashboard
    app.add_route("/", DashboardResource())
    app.add_route("/api/queue_table", QueueTableResource())
    app.add_route("/favicon.ico", FaviconResource())

    # Config / Admin
    app.add_route("/config", ConfigResource())
    app.add_route("/admin", AdminRedirectResource())
    app.add_route("/admin/users", AdminUsersResource())
    app.add_route("/admin/invites/create", AdminInvitesCreateResource())
    app.add_route("/admin/invites/{invite_id}/revoke", AdminInvitesRevokeResource())
    app.add_route("/admin/invites/{invite_id}/resend", AdminInvitesResendResource())
    app.add_route("/accept-invite", AcceptInviteResource())
    app.add_route("/admin/alerts", AdminAlertsResource())
    app.add_route("/admin/notifications", AdminAlertsResource())
    app.add_route("/admin/notifications/destinations", AdminDestinationsResource())
    app.add_route("/admin/credentials", AdminCredentialsResource())
    app.add_route(
        "/admin/credentials/{credential_id}/delete", AdminCredentialDeleteResource()
    )

    # Direct asset creation
    app.add_route("/repo", RepositoryResource())
    app.add_route("/image", ImageResource())
    app.add_route("/major_components", MajorComponentResource())

    # Refs; git ls-remote / skopeo tag queries
    app.add_route("/api/repos/{repo_id}/refs", RepoRefsResource())
    app.add_route("/api/images/{image_id}/refs", ImageRefsResource())
    app.add_route("/api/images/{image_id}/link_repo", ImageLinkRepoResource())
    app.add_route("/api/remote_refs/repo", RemoteRepoRefsResource())
    app.add_route("/api/remote_refs/image", RemoteImageRefsResource())

    # Reports and manual scan triggers
    app.add_route("/scan", ScanResource())
    app.add_route("/reports/{report_id}", ReportResource())

    # Products
    app.add_route("/products", ProductResource())
    app.add_route("/products/{product_id}", ProductDashboardResource())
    app.add_route("/products/{product_id}/delete", ProductDeleteResource())
    app.add_route("/products/{product_id}/permissions", ProductPermissionsResource())

    # Releases; order matters: static segments before parameterised ones
    app.add_route("/releases", ReleaseResource())
    app.add_route("/releases/helm", ReleaseHelmResource())
    app.add_route("/releases/{release_id}/assets", ReleaseAssetResource())
    app.add_route("/releases/assets/{release_asset_id}", ReleaseAssetDetailResource())
    from rover.routes.releases import AssetScanResource

    app.add_route("/releases/assets/{release_asset_id}/scan", AssetScanResource())
    app.add_route("/api/assets/{release_asset_id}/scans", AssetScanResource())
    app.add_route("/releases/{release_id}/scan", ReleaseScanResource())
    app.add_route("/releases/{release_id}/eol", ReleaseEolResource())
    app.add_route("/releases/{release_id}/delete", ReleaseDeleteResource())
    app.add_route("/releases/{release_id}", ReleaseDashboardResource())

    # Release asset HTMX partials
    app.add_route(
        "/api/releases/{release_id}/assets_table", ReleaseAssetsTableResource()
    )
    app.add_route(
        "/api/releases/{release_id}/major_component_cards",
        ReleaseMajorComponentCardsResource(),
    )

    # Helm chart discovery
    app.add_route("/api/helm/repo/charts", HelmRepoChartsResource())

    # Settings; API token & Notification management
    app.add_route("/settings/tokens", ApiTokenPageResource())
    app.add_route("/settings/tokens/create", ApiTokenCreateResource())
    app.add_route("/settings/tokens/{token_id}/revoke", ApiTokenRevokeResource())

    from rover.routes.notifications import (
        NotificationDestinationCreateResource,
        NotificationDestinationDeleteResource,
        NotificationDestinationSetDefaultResource,
        NotificationDestinationTestResource,
        NotificationDestinationUpdateResource,
        NotificationRuleCreateResource,
        NotificationRuleDeleteResource,
        ProductNotificationsPageResource,
        UserNotificationsPageResource,
    )

    app.add_route("/user/settings/notifications", UserNotificationsPageResource())
    app.add_route(
        "/products/{product_id}/settings/notifications",
        ProductNotificationsPageResource(),
    )
    app.add_route(
        "/api/notifications/destinations", NotificationDestinationCreateResource()
    )
    app.add_route(
        "/api/notifications/destinations/{dest_id}/delete",
        NotificationDestinationDeleteResource(),
    )
    app.add_route(
        "/api/notifications/destinations/{dest_id}/update",
        NotificationDestinationUpdateResource(),
    )
    app.add_route(
        "/api/notifications/destinations/{dest_id}/set-default",
        NotificationDestinationSetDefaultResource(),
    )
    app.add_route(
        "/api/notifications/destinations/{dest_id}/test",
        NotificationDestinationTestResource(),
    )
    app.add_route("/api/notifications/rules", NotificationRuleCreateResource())
    app.add_route(
        "/api/notifications/rules/{rule_id}/delete",
        NotificationRuleDeleteResource(),
    )

    # Machine-to-machine JSON API & Interactive OpenAPI Specs
    from rover.routes.api import OpenApiDocsResource, OpenApiJsonResource

    app.add_route("/api/ci/image-metadata", CiImageMetadataResource())
    app.add_route("/api/openapi.json", OpenApiJsonResource())
    app.add_route("/api/docs", OpenApiDocsResource())
    app.add_route("/api/swagger", OpenApiDocsResource())
    app.add_route("/docs/swagger", OpenApiDocsResource())
    app.add_route("/docs", OpenApiDocsResource())

    # Schedule management routes
    from rover.routes.schedules import (
        ProductSchedulesPageResource,
        ProductSchedulesResource,
        ScheduleDetailResource,
        ScheduleLogsResource,
    )

    app.add_route("/products/{product_id}/schedules", ProductSchedulesPageResource())
    app.add_route("/api/products/{product_id}/schedules", ProductSchedulesResource())
    app.add_route("/api/schedules/{schedule_id}", ScheduleDetailResource())
    app.add_route("/api/schedules/{schedule_id}/logs", ScheduleLogsResource())

    return app
