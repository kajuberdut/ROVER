"""rover/routes/settings.py: API token management routes."""

import falcon
import falcon.asgi

from rover import db
from rover.routes._env import respond_action, template_env


def _check_can_manage_tokens(req: falcon.asgi.Request) -> None:
    """Raise HTTP 401 if the requesting user is not authenticated."""
    user = getattr(req.context, "user", None)
    if not user:
        raise falcon.HTTPUnauthorized(description="Authentication required.")


class ApiTokenPageResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        _check_can_manage_tokens(req)
        user = req.context.user
        tokens = db.get_user_api_tokens(user["sub"])
        template = template_env.get_template("settings_tokens.html")

        # Check if we just created a token and need to display it
        new_token = req.get_param("new_token")

        resp.text = template.render(
            user=user,
            title="API Tokens",
            tokens=tokens,
            new_token=new_token,
        )
        resp.content_type = falcon.MEDIA_HTML


class ApiTokenCreateResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        _check_can_manage_tokens(req)
        form = await req.get_media()
        name = form.get("token_name")
        permission = form.get("token_permission")

        if not name or permission not in ("read", "write"):
            raise falcon.HTTPBadRequest(description="Invalid token parameters.")

        user = req.context.user
        cleartext_token, _ = db.create_api_token(user["sub"], name, permission)

        redirect_url = f"/settings/tokens?new_token={cleartext_token}"
        respond_action(
            req, resp, redirect_url, extra_json={"new_token": cleartext_token}
        )


class ApiTokenRevokeResource:
    async def on_post(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response, token_id: str
    ) -> None:
        _check_can_manage_tokens(req)
        user = req.context.user
        db.revoke_api_token(token_id, user["sub"])
        db.log_audit_event(
            action="user.api_token_revoke",
            resource_type="api_token",
            resource_id=token_id,
            user_sub=user.get("sub"),
            user_email=user.get("email"),
            ip_address=req.remote_addr,
        )
        respond_action(req, resp, "/settings/tokens")
