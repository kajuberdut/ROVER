import logging
import os
import urllib.parse
import uuid
from typing import Any

import falcon
import falcon.asgi
import requests  # type: ignore[import-untyped]
from authlib.jose import jwt  # type: ignore[import-untyped]
from itsdangerous import BadSignature, URLSafeSerializer

from rover import db

log = logging.getLogger(__name__)

# OIDC Configuration
# For redirects, the user's browser needs the public resolvable URL
OIDC_AUTHORIZATION_ENDPOINT = "https://auth.rover.local/api/oidc/authorization"
# For backend requests, we use the internal docker network URL
OIDC_TOKEN_ENDPOINT = "http://authelia:9091/api/oidc/token"  # noqa: S105
OIDC_JWKS_URI = "http://authelia:9091/jwks.json"
# The callback URI must match what goes through the external proxy
OIDC_REDIRECT_URI = "https://rover.local/callback"

OIDC_CLIENT_ID = "rover-client"
# Read from env in production; fallback is the dev default set by setup.sh
OIDC_CLIENT_SECRET = os.environ.get("ROVER_OIDC_CLIENT_SECRET", "rover-secret")

# Session Configuration
SESSION_SECRET = os.environ.get(
    "ROVER_SECRET_KEY", "fallback_secret_key_change_in_production"
)
cookie_serializer = URLSafeSerializer(SESSION_SECRET)
COOKIE_NAME = "rover_session"

# Cache for JWKS to avoid fetching keys on every request
_cached_jwks = None


def get_jwks() -> dict[str, object]:
    global _cached_jwks
    if not _cached_jwks:
        try:
            resp = requests.get(
                OIDC_JWKS_URI,
                timeout=5,
                headers={
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-Host": "auth.rover.local",
                },
            )
            resp.raise_for_status()
            _cached_jwks = dict(resp.json())
        except Exception as e:
            log.error(f"Failed to fetch JWKS: {e}")
            raise
    return _cached_jwks


def generate_authelia_argon2_hash(password: str) -> str:
    """Generates an Argon2id password hash for Authelia using argon2-cffi or container fallback."""
    try:
        import argon2  # type: ignore[import-untyped]

        hasher = argon2.PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=16,
            type=argon2.Type.ID,
        )
        return hasher.hash(password)
    except Exception as e:
        log.warning(
            f"In-process argon2 hashing failed, attempting container fallback: {e}"
        )

    import shutil
    import subprocess

    docker_bin = shutil.which("docker") or "docker"

    # Try container exec fallback
    try:
        res = subprocess.run(  # noqa: S603
            [
                docker_bin,
                "exec",
                "authelia",
                "authelia",
                "crypto",
                "hash",
                "generate",
                "argon2",
                "--password",
                password,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if res.returncode == 0 and "$argon2" in res.stdout:
            for line in res.stdout.splitlines():
                if "$argon2" in line:
                    return line.strip().split()[-1]
    except Exception as e:
        log.warning(f"Container exec for argon2 hashing failed: {e}")

    raise RuntimeError("Failed to generate Authelia password hash.")


def add_authelia_user(
    username: str,
    email: str,
    password: str,
    display_name: str | None = None,
    authelia_db_path: str = "authelia/users_database.yml",
) -> None:
    """Registers a new user in Authelia's users_database.yml file."""
    import fcntl
    import os

    import yaml  # type: ignore[import-untyped]

    target_path = authelia_db_path
    if not os.path.exists(target_path):
        alt_path = os.path.join(os.getcwd(), "authelia", "users_database.yml")
        if os.path.exists(alt_path):
            target_path = alt_path

    username_clean = username.strip().lower()
    email_clean = email.strip()
    disp_name = display_name or username_clean.title()
    password_hash = generate_authelia_argon2_hash(password)

    # Open file with exclusive lock to prevent concurrent write corruption
    flags = os.O_RDWR | os.O_CREAT
    fd = os.open(target_path, flags, 0o644)
    with os.fdopen(fd, "r+", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            content = f.read()
            data = yaml.safe_load(content) if content else {"users": {}}
            if (
                not isinstance(data, dict)
                or "users" not in data
                or not isinstance(data["users"], dict)
            ):
                data = {"users": {}}

            data["users"][username_clean] = {
                "disabled": False,
                "displayname": disp_name,
                "password": password_hash,
                "email": email_clean,
                "groups": ["users"],
            }

            f.seek(0)
            f.truncate()
            yaml.safe_dump(data, f, sort_keys=False)
            f.flush()
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    # Trigger Authelia container restart so it reloads users_database.yml into memory
    try:
        import docker  # type: ignore[import-untyped]

        client = docker.from_env()  # type: ignore[attr-defined]
        authelia_container = client.containers.get("authelia")
        authelia_container.restart()
        log.info("Restarted authelia container to apply new user configuration.")
    except Exception as e:
        log.warning(f"Could not restart authelia container via docker SDK: {e}")


def update_authelia_user_password(
    username_or_email: str,
    new_password: str,
    authelia_db_path: str = "authelia/users_database.yml",
) -> None:
    """Updates a user's password in Authelia users_database.yml and local users table."""
    import fcntl
    import os

    import yaml  # type: ignore[import-untyped]

    target_path = authelia_db_path
    if not os.path.exists(target_path):
        alt_path = os.path.join(os.getcwd(), "authelia", "users_database.yml")
        if os.path.exists(alt_path):
            target_path = alt_path

    clean_target = username_or_email.strip().lower()
    password_hash = generate_authelia_argon2_hash(new_password)

    if os.path.exists(target_path):
        flags = os.O_RDWR | os.O_CREAT
        fd = os.open(target_path, flags, 0o644)
        with os.fdopen(fd, "r+", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                content = f.read()
                data = yaml.safe_load(content) if content else {"users": {}}
                if (
                    isinstance(data, dict)
                    and "users" in data
                    and isinstance(data["users"], dict)
                ):
                    matched_username = None
                    for uname, uinfo in data["users"].items():
                        if (
                            uname.lower() == clean_target
                            or str(uinfo.get("email", "")).lower() == clean_target
                        ):
                            matched_username = uname
                            break

                    if matched_username:
                        data["users"][matched_username]["password"] = password_hash
                        f.seek(0)
                        f.truncate()
                        yaml.safe_dump(data, f, sort_keys=False)
                        f.flush()
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        try:
            import docker  # type: ignore[import-not-found]

            client = docker.from_env()  # type: ignore[attr-defined]
            authelia_container = client.containers.get("authelia")
            authelia_container.restart()
            log.info("Restarted authelia container after updating password.")
        except Exception as e:
            log.warning(f"Could not restart authelia container via docker SDK: {e}")


def set_user_session_cookie(
    resp: falcon.asgi.Response,
    req: falcon.asgi.Request | None,
    user: dict[str, Any],
    max_age: int = 86400 * 7,
) -> dict[str, Any]:
    """Establishes an authenticated session cookie for a given user dict."""
    session_data = {
        "sub": user["sub"],
        "email": user.get("email") or user["sub"],
        "name": user.get("name") or str(user.get("email", user["sub"])).split("@")[0],
        "role": user.get("role") or "viewer",
        "product_ids": db.get_user_product_ids(user["sub"]),
    }
    cookie_val = cookie_serializer.dumps(session_data)
    resp.set_cookie(
        COOKIE_NAME,
        cookie_val,
        max_age=max_age,
        path="/",
        secure=False,
        http_only=True,
    )
    if req is not None:
        req.context.user = session_data
    return session_data


class RequireAuthMiddleware:
    """
    Falcon ASGI Middleware to require authentication on all routes
    except login, callback, email verification, password reset, and static assets.
    Enforces restricted portal navigation for 'email_only' users.
    """

    async def process_request(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        # 1. Parse session cookie if present on any route
        session_cookie = req.cookies.get(COOKIE_NAME)
        if session_cookie:
            try:
                session_data = cookie_serializer.loads(session_cookie)
                req.context.user = session_data
                if session_data.get("role") == "email_only" and not (
                    req.path.startswith("/user/subscriptions")
                    or req.path.startswith("/static")
                    or req.path in ["/confirm-email", "/logout", "/login"]
                ):
                    raise falcon.HTTPFound("/user/subscriptions")
                return
            except falcon.HTTPFound:
                raise
            except (BadSignature, Exception) as e:
                log.debug("Session cookie unparseable: %s", e)

        # 2. Check for public routes if no session cookie
        is_public = (
            req.path
            in [
                "/login",
                "/callback",
                "/accept-invite",
                "/confirm-email",
                "/forgot-password",
                "/reset-password",
                "/user/subscriptions",
                "/api/openapi.json",
            ]
            or req.path.startswith("/static")
            or req.path.startswith("/docs")
            or req.path.startswith("/api/docs")
            or req.path.startswith("/api/swagger")
        )
        if is_public:
            return

        # 3. Check for API token (Authorization: Bearer <token>)
        auth_header = req.get_header("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            token_data = db.verify_api_token(token)
            if token_data:
                db_user = db.get_user(token_data["user_sub"])
                if db_user:
                    req.context.user = {
                        "sub": db_user["sub"],
                        "email": db_user["email"],
                        "name": db_user["name"],
                        "role": db_user["role"],
                        "product_ids": db.get_user_product_ids(db_user["sub"]),
                        "api_token_permission": token_data["permission"],
                        "api_token_id": token_data["id"],
                    }
                    if db_user["role"] == "email_only" and not req.path.startswith(
                        "/user/subscriptions"
                    ):
                        raise falcon.HTTPFound("/user/subscriptions")
                    return
            raise falcon.HTTPUnauthorized(description="Invalid API token")

        next_param = urllib.parse.quote(req.relative_uri)
        raise falcon.HTTPFound(f"/login?next={next_param}")


# --- Falcon Resources ---


class LoginResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        next_url = req.get_param("next") or req.get_param("rd") or "/"
        if not next_url.startswith("/") or next_url.startswith("//"):
            next_url = "/"

        # Generate random state and nonce to prevent CSRF and replay attacks
        state = str(uuid.uuid4())
        nonce = str(uuid.uuid4())

        # We store state, nonce, and target next_url in a temporary cookie
        temp_session = cookie_serializer.dumps(
            {"state": state, "nonce": nonce, "next": next_url}
        )
        resp.set_cookie(
            "rover_auth_state", temp_session, secure=False, http_only=True, path="/"
        )

        params = {
            "client_id": OIDC_CLIENT_ID,
            "redirect_uri": OIDC_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
        }

        url = f"{OIDC_AUTHORIZATION_ENDPOINT}?{urllib.parse.urlencode(params)}"
        raise falcon.HTTPFound(url)


class CallbackResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        # We need async requests for ASGI. We'll run the blocking requests in a thread.
        import asyncio

        code = req.get_param("code")
        state = req.get_param("state")
        error = req.get_param("error")

        if error:
            resp.text = f"Authentication Error: {error}"
            resp.status = falcon.HTTP_400
            return

        state_cookie = req.cookies.get("rover_auth_state")
        if not state_cookie:
            resp.text = "Missing authentication state cookie."
            resp.status = falcon.HTTP_400
            return

        try:
            state_data = cookie_serializer.loads(state_cookie)
        except BadSignature:
            resp.text = "Invalid authentication state."
            resp.status = falcon.HTTP_400
            return

        if state != state_data.get("state"):
            resp.text = "State mismatch. Potential CSRF attack."
            resp.status = falcon.HTTP_400
            return

        # Clean up state cookie
        resp.unset_cookie("rover_auth_state")

        # Exchange code for token.
        # Authelia requires client credentials via HTTP Basic Auth, not in the body.
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": OIDC_REDIRECT_URI,
        }

        try:
            token_resp = await asyncio.to_thread(
                requests.post,
                OIDC_TOKEN_ENDPOINT,
                data=token_data,
                auth=(OIDC_CLIENT_ID, OIDC_CLIENT_SECRET),
                headers={
                    "X-Forwarded-Proto": "https",
                    "X-Forwarded-Host": "auth.rover.local",
                },
                timeout=5,
            )
            token_resp.raise_for_status()
            tokens = token_resp.json()
        except Exception as e:
            log.error(f"Token exchange failed: {e}")
            resp.text = "Failed to exchange authorization code for token."
            resp.status = falcon.HTTP_500
            return

        id_token = tokens.get("id_token")
        if not id_token:
            resp.text = "Missing id_token in provider response."
            resp.status = falcon.HTTP_500
            return

        # Validate JWT using Authlib
        try:
            jwks = await asyncio.to_thread(get_jwks)
            claims = jwt.decode(
                id_token,
                jwks,
                claims_options={
                    # Not validating iss here because Authelia's internal issuer
                    # (localhost:9091) differs from the browser-facing one.
                    # Nonce and aud still protect against replay/misdirection.
                    "aud": {"essential": True, "value": OIDC_CLIENT_ID},
                },
            )
            # Verify the claims
            claims.validate()
        except Exception as e:
            log.error(f"JWT validation failed: {e}")
            resp.text = f"Invalid id_token: {e}"
            resp.status = falcon.HTTP_400
            return

        # Verify Nonce
        if claims.get("nonce") != state_data.get("nonce"):
            resp.text = "Nonce mismatch."
            resp.status = falcon.HTTP_400
            return

        # Authentication successful!
        # Fetch userinfo from Authelia to get email/name; these aren't always
        # in the id_token JWT for flat-file users, but are available via userinfo.
        access_token = tokens.get("access_token")
        userinfo = {}
        if access_token:
            try:
                ui_resp = await asyncio.to_thread(
                    requests.get,
                    "http://authelia:9091/api/oidc/userinfo",
                    headers={
                        "Authorization": f"Bearer {access_token}",
                        "X-Forwarded-Proto": "https",
                        "X-Forwarded-Host": "auth.rover.local",
                    },
                    timeout=5,
                )
                if ui_resp.ok:
                    userinfo = ui_resp.json()
            except Exception as e:
                log.warning(f"Userinfo fetch failed (non-fatal): {e}")

        sub = claims.get("sub")
        email = userinfo.get("email") or claims.get("email")
        name = (
            userinfo.get("name")
            or userinfo.get("preferred_username")
            or claims.get("name")
            or claims.get("preferred_username")
        )

        # Determine system role from Identity Provider groups (hybrid model)
        raw_groups = (
            claims.get("groups")
            or userinfo.get("groups")
            or claims.get("roles")
            or userinfo.get("roles")
        )
        role = None
        if raw_groups is not None:
            if isinstance(raw_groups, str):
                group_list = [raw_groups]
            elif isinstance(raw_groups, (list, tuple)):
                group_list = [str(g) for g in raw_groups]
            else:
                group_list = []

            admin_groups = {
                "admins",
                "admin",
                "system_admin",
                "system_admins",
                "rover_admin",
                "rover_admins",
            }
            is_admin = any(g.lower() in admin_groups for g in group_list)
            role = "system_admin" if is_admin else "viewer"

        # Upsert user into ROVER's user registry and sync IdP role.
        db_user = db.upsert_user(sub=sub, email=email, name=name, role=role)

        # Set persistent secure cookie for ROVER
        set_user_session_cookie(resp, req, db_user, max_age=86400)

        # Redirect to target page (defaulting to dashboard)
        next_url = state_data.get("next") or "/"
        if not next_url.startswith("/") or next_url.startswith("//"):
            next_url = "/"

        raise falcon.HTTPFound(next_url)


class LogoutResource:
    async def on_get(
        self, req: falcon.asgi.Request, resp: falcon.asgi.Response
    ) -> None:
        # Unset local session
        resp.unset_cookie(COOKIE_NAME)
        # Redirect to Authelia's logout endpoint
        url = "https://auth.rover.local/logout?rd=https://rover.local"
        raise falcon.HTTPFound(url)
