"""src/rover/tokens.py — Unified Token Generation & Verification Module for ROVER."""

import logging
import secrets
from typing import Any

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from rover import db
from rover.auth import SESSION_SECRET

logger = logging.getLogger(__name__)

# Serializers with distinct salts for cryptographic domain separation
_email_serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="email-verification")
_password_serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="password-reset")
_magic_serializer = URLSafeTimedSerializer(SESSION_SECRET, salt="magic-access-token")


# --- 1. Email Verification Tokens ---


def generate_email_verification_token(
    email: str, target_type: str = "user", target_id: str | None = None
) -> str:
    """Generates a cryptographically signed email verification token valid for 24 hours."""
    payload = {"email": email, "type": target_type, "id": target_id}
    return str(_email_serializer.dumps(payload))


def verify_email_verification_token(
    token: str, max_age: int = 86400
) -> dict[str, Any] | None:
    """Verifies an email verification token. Returns payload dict or None if invalid/expired."""
    try:
        data = _email_serializer.loads(token, max_age=max_age)
        if isinstance(data, dict):
            return data
    except (BadSignature, SignatureExpired) as e:
        logger.warning(f"Email verification token invalid or expired: {e}")
    return None


# --- 2. Password Reset Tokens ---


def generate_password_reset_token(email_or_sub: str) -> str:
    """Generates a cryptographically signed password reset token valid for 24 hours."""
    user = db.get_user_by_email(email_or_sub) or db.get_user(email_or_sub)
    pw_hash = user.get("password_hash") if user else ""
    payload = {"sub_or_email": email_or_sub, "ph": pw_hash}
    return str(_password_serializer.dumps(payload))


def verify_password_reset_token(token: str, max_age: int = 86400) -> str | None:
    """Verifies a password reset token. Returns target sub/email string or None if invalid, expired, or reused."""
    try:
        data = _password_serializer.loads(token, max_age=max_age)
        if isinstance(data, dict) and "sub_or_email" in data:
            email_or_sub = str(data["sub_or_email"])
            token_ph = data.get("ph")
            user = db.get_user_by_email(email_or_sub) or db.get_user(email_or_sub)
            if user:
                current_ph = user.get("password_hash")
                if token_ph != current_ph:
                    logger.warning(
                        f"Password reset token reused or invalidated for '{email_or_sub}'."
                    )
                    return None
            return email_or_sub
    except (BadSignature, SignatureExpired) as e:
        logger.warning(f"Password reset token invalid or expired: {e}")
    return None


# --- 3. Passwordless Magic Access Tokens ---


def generate_magic_access_token(email: str) -> str:
    """Generates a cryptographically signed magic access token for passwordless subscriptions portal access."""
    payload = {"email": email}
    return str(_magic_serializer.dumps(payload))


def verify_magic_access_token(token: str, max_age: int = 86400) -> str | None:
    """Verifies a magic access token. Returns email string or None if invalid/expired."""
    try:
        data = _magic_serializer.loads(token, max_age=max_age)
        if isinstance(data, dict) and "email" in data:
            return str(data["email"])
    except (BadSignature, SignatureExpired) as e:
        logger.warning(f"Magic access token invalid or expired: {e}")
    return None


# --- 4. User Invitation Secret Tokens ---


def generate_invite_token(nbytes: int = 32) -> str:
    """Generates a cryptographically secure random token string for user invitations."""
    return secrets.token_urlsafe(nbytes)


# --- 5. Unified Action Link Builders ---


def build_verification_url(token: str, base_url: str = "https://rover.local") -> str:
    """Constructs a full email verification URL."""
    return f"{base_url.rstrip('/')}/confirm-email?token={token}"


def build_password_reset_url(token: str, base_url: str = "https://rover.local") -> str:
    """Constructs a full password reset URL."""
    return f"{base_url.rstrip('/')}/reset-password?token={token}"


def build_magic_access_url(token: str, base_url: str = "https://rover.local") -> str:
    """Constructs a full magic access subscription URL."""
    return f"{base_url.rstrip('/')}/user/subscriptions?token={token}"


def build_invite_url(token: str, base_url: str = "https://rover.local") -> str:
    """Constructs a full invitation acceptance URL."""
    return f"{base_url.rstrip('/')}/accept-invite?token={token}"
