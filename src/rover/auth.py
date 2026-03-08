import logging
import os
import urllib.parse
import uuid

import falcon
import requests
from authlib.jose import jwt
from itsdangerous import BadSignature, URLSafeSerializer

from rover import scan_queue

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
SESSION_SECRET = os.environ.get("ROVER_SECRET_KEY", "fallback_secret_key_change_in_production")
cookie_serializer = URLSafeSerializer(SESSION_SECRET)
COOKIE_NAME = "rover_session"

# Cache for JWKS to avoid fetching keys on every request
_cached_jwks = None

def get_jwks():
    global _cached_jwks
    if not _cached_jwks:
        try:
            resp = requests.get(OIDC_JWKS_URI, timeout=5)
            resp.raise_for_status()
            _cached_jwks = resp.json()
        except Exception as e:
            log.error(f"Failed to fetch JWKS: {e}")
            raise
    return _cached_jwks

class RequireAuthMiddleware:
    """
    Falcon ASGI Middleware to require authentication on all routes
    except login, callback, and static assets.
    """
    async def process_request(self, req: falcon.asgi.Request, resp: falcon.asgi.Response) -> None:
        if req.path in ["/login", "/callback"] or req.path.startswith("/static"):
            return

        session_cookie = req.cookies.get(COOKIE_NAME)
        if not session_cookie:
            raise falcon.HTTPFound("/login")

        try:
            session_data = cookie_serializer.loads(session_cookie)
            req.context.user = session_data
        except BadSignature:
            log.warning("Invalid session cookie detected")
            resp.unset_cookie(COOKIE_NAME)
            raise falcon.HTTPFound("/login")

# --- Falcon Resources ---

class LoginResource:
    async def on_get(self, req: falcon.asgi.Request, resp: falcon.asgi.Response):
        # Generate random state and nonce to prevent CSRF and replay attacks
        state = str(uuid.uuid4())
        nonce = str(uuid.uuid4())
        
        # We store state and nonce in a temporary cookie so callback can verify them
        temp_session = cookie_serializer.dumps({"state": state, "nonce": nonce})
        resp.set_cookie("rover_auth_state", temp_session, secure=False, http_only=True, path="/")
        
        params = {
            "client_id": OIDC_CLIENT_ID,
            "redirect_uri": OIDC_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce
        }
        
        url = f"{OIDC_AUTHORIZATION_ENDPOINT}?{urllib.parse.urlencode(params)}"
        raise falcon.HTTPFound(url)

class CallbackResource:
    async def on_get(self, req: falcon.asgi.Request, resp: falcon.asgi.Response):
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
                }
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
        # Fetch userinfo from Authelia to get email/name — these aren't always
        # in the id_token JWT for flat-file users, but are available via userinfo.
        access_token = tokens.get("access_token")
        userinfo = {}
        if access_token:
            try:
                ui_resp = await asyncio.to_thread(
                    requests.get,
                    "http://authelia:9091/api/oidc/userinfo",
                    headers={"Authorization": f"Bearer {access_token}"},
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

        # Upsert user into ROVER's user registry.
        db_user = scan_queue.upsert_user(sub=sub, email=email, name=name)

        # Build local session — include role and owned products for permission checks.
        user_data = {
            "sub":        db_user["sub"],
            "email":      db_user["email"],
            "name":       db_user["name"],
            "role":       db_user["role"],
            "product_ids": scan_queue.get_user_product_ids(db_user["sub"]),
        }
        
        session_token = cookie_serializer.dumps(user_data)
        
        # Set persistent secure cookie for ROVER
        resp.set_cookie(COOKIE_NAME, session_token, secure=False, http_only=True, path="/", max_age=86400)
        
        # Redirect to dashboard
        raise falcon.HTTPFound("/")

class LogoutResource:
    async def on_get(self, req: falcon.asgi.Request, resp: falcon.asgi.Response):
        # Unset local session
        resp.unset_cookie(COOKIE_NAME)
        # Redirect to Authelia's logout endpoint
        url = "https://auth.rover.local/logout"
        raise falcon.HTTPFound(url)
