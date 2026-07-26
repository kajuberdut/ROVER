"""src/rover/vault.py — OpenBao REST API client for dynamic secret storage and retrieval."""

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger(__name__)

DEFAULT_VAULT_ADDR = "http://openbao:8200"


def get_vault_addr() -> str:
    addr = os.getenv("VAULT_ADDR") or os.getenv("OPENBAO_ADDR") or DEFAULT_VAULT_ADDR
    return addr.rstrip("/")


class OpenBaoClient:
    """REST API client for interacting with OpenBao KV v2 secrets engine."""

    def __init__(self, vault_addr: str | None = None) -> None:
        self.vault_addr = (vault_addr or get_vault_addr()).rstrip("/")
        self.token: str | None = (
            os.getenv("VAULT_TOKEN") or os.getenv("OPENBAO_TOKEN") or os.getenv("BAO_TOKEN")
        )

    def _get_headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["X-Vault-Token"] = self.token
        return headers

    def authenticate_approle(
        self, role_id: str | None = None, secret_id: str | None = None
    ) -> bool:
        """Authenticate using AppRole credentials to obtain a client token."""
        role_id = role_id or os.getenv("OPENBAO_ROLE_ID") or os.getenv("BAO_ROLE_ID")
        secret_id = (
            secret_id or os.getenv("OPENBAO_SECRET_ID") or os.getenv("BAO_SECRET_ID")
        )

        if not role_id or not secret_id:
            logger.warning(
                "AppRole credentials (OPENBAO_ROLE_ID / OPENBAO_SECRET_ID / BAO_ROLE_ID / BAO_SECRET_ID) missing."
            )
            return False

        url = f"{self.vault_addr}/v1/auth/approle/login"
        payload = json.dumps({"role_id": role_id, "secret_id": secret_id}).encode(
            "utf-8"
        )
        req = urllib.request.Request(  # noqa: S310
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                res_data = json.loads(resp.read().decode("utf-8"))
                auth_info = res_data.get("auth", {})
                self.token = auth_info.get("client_token")
                logger.info("Successfully authenticated with OpenBao via AppRole.")
                return True
        except Exception as e:
            logger.error(f"Failed to authenticate with OpenBao AppRole: {e}")
            return False

    def ensure_authenticated(self) -> bool:
        """Ensures a token is available or attempts AppRole login."""
        if self.token:
            return True
        return self.authenticate_approle()

    def write_secret(self, path: str, secret_data: dict[str, Any]) -> bool:
        """Writes a secret dictionary to KV v2 path (kv/data/{path})."""
        if not self.ensure_authenticated():
            logger.warning("OpenBao unauthenticated; skipping remote secret write.")
            return False

        clean_path = path.lstrip("/")
        if not clean_path.startswith("kv/data/") and not clean_path.startswith(
            "secret/data/"
        ):
            clean_path = f"kv/data/{clean_path}"

        import urllib.parse
        quoted_path = urllib.parse.quote(clean_path, safe="/")

        url = f"{self.vault_addr}/v1/{quoted_path}"
        payload = json.dumps({"data": secret_data}).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310
            url, data=payload, headers=self._get_headers(), method="POST"
        )

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return resp.status in (200, 204)
        except Exception as e:
            logger.error(f"Failed writing secret to OpenBao at {path}: {e}")
            return False

    def read_secret(self, path: str) -> dict[str, Any] | None:
        """Reads a secret dictionary from KV v2 path (kv/data/{path})."""
        if not self.ensure_authenticated():
            logger.warning("OpenBao unauthenticated; cannot read secret.")
            return None

        clean_path = path.lstrip("/")
        if not clean_path.startswith("kv/data/") and not clean_path.startswith(
            "secret/data/"
        ):
            clean_path = f"kv/data/{clean_path}"

        import urllib.parse
        quoted_path = urllib.parse.quote(clean_path, safe="/")

        url = f"{self.vault_addr}/v1/{quoted_path}"
        req = urllib.request.Request(url, headers=self._get_headers(), method="GET")  # noqa: S310

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                res_data = json.loads(resp.read().decode("utf-8"))
                return dict(res_data.get("data", {}).get("data", {}))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return None
            logger.error(f"HTTP error reading secret from OpenBao at {path}: {e}")
            return None
        except Exception as e:
            logger.error(f"Failed reading secret from OpenBao at {path}: {e}")
            return None

    def delete_secret(self, path: str) -> bool:
        """Deletes/destroys a secret from KV v2 path (kv/metadata/{path})."""
        if not self.ensure_authenticated():
            return False

        clean_path = path.lstrip("/")
        if clean_path.startswith("kv/data/"):
            clean_path = clean_path.replace("kv/data/", "kv/metadata/", 1)
        elif not clean_path.startswith("kv/metadata/"):
            clean_path = f"kv/metadata/{clean_path}"

        import urllib.parse
        quoted_path = urllib.parse.quote(clean_path, safe="/")

        url = f"{self.vault_addr}/v1/{quoted_path}"
        req = urllib.request.Request(url, headers=self._get_headers(), method="DELETE")  # noqa: S310

        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
                return resp.status in (200, 204)
        except Exception as e:
            logger.error(f"Failed deleting secret from OpenBao at {path}: {e}")
            return False


def get_authenticated_git_url_info(
    target_url: str,
    product_id: str | None = None,
    credential_id: str | None = None,
    vault_client: OpenBaoClient | None = None,
) -> tuple[str, dict[str, Any] | None]:
    """Injects Git authentication token into HTTPS Git URLs if a token exists in Vault or env.

    Returns tuple of (authenticated_url, credential_used_metadata).
    """
    if not target_url or (
        not target_url.startswith("http://") and not target_url.startswith("https://")
    ):
        return target_url, None

    import urllib.parse

    parsed = urllib.parse.urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        return target_url, None

    if parsed.username or parsed.password:
        return target_url, None

    from rover import db

    token: str | None = None
    cred_info: dict[str, Any] | None = None

    # 1. If explicit credential_id passed (and not "auto")
    if credential_id and credential_id != "auto":
        cred = db.get_credential_by_id(credential_id)
        if cred:
            token = db.get_unmasked_secret(
                name=cred["name"],
                scope=cred["scope"],
                product_id=cred.get("product_id"),
                vault_client=vault_client,
            )
            if token:
                cred_info = {
                    "id": cred["id"],
                    "name": cred["name"],
                    "type": cred["type"],
                    "scope": cred["scope"],
                }

    # 2. Automatic lookup if no explicit token found
    if not token:
        token, cred_info = db.get_unmasked_secret_by_type_info(
            credential_type="git_token",
            hostname=hostname,
            product_id=product_id,
            vault_client=vault_client,
        )

    # 3. Environment variable fallback
    if not token:
        env_token = os.getenv("GITHUB_TOKEN") or os.getenv("GIT_TOKEN")
        if env_token:
            token = env_token
            cred_info = {"id": "env", "name": "Environment Token", "scope": "env"}

    if not token:
        return target_url, None

    if ":" in token:
        auth_netloc = f"{token}@{hostname}"
    elif "github.com" in hostname:
        auth_netloc = f"x-access-token:{token}@{hostname}"
    elif "gitlab" in hostname:
        auth_netloc = f"oauth2:{token}@{hostname}"
    else:
        auth_netloc = f"{token}@{hostname}"

    if parsed.port:
        auth_netloc = f"{auth_netloc}:{parsed.port}"

    authenticated_url = urllib.parse.urlunparse(
        (
            parsed.scheme,
            auth_netloc,
            parsed.path,
            parsed.params,
            parsed.query,
            parsed.fragment,
        )
    )
    return authenticated_url, cred_info


def get_authenticated_git_url(
    target_url: str,
    product_id: str | None = None,
    credential_id: str | None = None,
    vault_client: OpenBaoClient | None = None,
) -> str:
    url, _ = get_authenticated_git_url_info(
        target_url=target_url,
        product_id=product_id,
        credential_id=credential_id,
        vault_client=vault_client,
    )
    return url


def sanitize_git_url(url: str) -> str:
    """Strips embedded auth credentials from a Git URL for safe logging and UI display."""
    if "@" in url and (url.startswith("http://") or url.startswith("https://")):
        import urllib.parse

        parsed = urllib.parse.urlparse(url)
        netloc = parsed.hostname
        if parsed.port:
            netloc = f"{netloc}:{parsed.port}"
        return urllib.parse.urlunparse(
            (
                parsed.scheme,
                netloc or "",
                parsed.path,
                parsed.params,
                parsed.query,
                parsed.fragment,
            )
        )
    return url
