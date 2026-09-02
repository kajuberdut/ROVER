"""src/rover/email_tokens.py — Email notification dispatch & token integration."""

import logging

from rover import db
from rover.notifications.transports import deliver_notification
from rover.tokens import (
    build_magic_access_url,
    build_password_reset_url,
    build_verification_url,
    generate_email_verification_token,
    generate_magic_access_token,
    generate_password_reset_token,
    verify_email_verification_token,
    verify_magic_access_token,
    verify_password_reset_token,
)

logger = logging.getLogger(__name__)

# Re-export token functions for backward compatibility
__all__ = [
    "generate_email_verification_token",
    "verify_email_verification_token",
    "generate_password_reset_token",
    "verify_password_reset_token",
    "generate_magic_access_token",
    "verify_magic_access_token",
    "send_system_email",
    "send_verification_email",
    "send_password_reset_email",
    "send_magic_access_email",
]


def send_system_email(to_email: str, subject: str, message: str) -> bool:
    """Delivers an email using the system default SMTP or AWS SES gateway."""
    dest = db.get_default_smtp_destination()
    if not dest:
        logger.warning(
            f"No default SMTP/SES gateway configured. System email to '{to_email}' skipped."
        )
        return False

    vault_secret = None
    if dest.get("vault_secret_path"):
        vault_secret = db.get_destination_unmasked_secret(dest["id"])

    payload = {
        "to_email": to_email,
        "title": subject,
        "message": message,
        "event_type": "system.email",
    }
    try:
        success = deliver_notification(dest, payload, vault_secret=vault_secret)
        status = "delivered" if success else "failed"
        http_status = 200 if success else 500
        error_msg = None if success else "Transport delivery returned false"
    except Exception as e:
        logger.error(f"Error delivering system email to '{to_email}': {e}")
        success = False
        status = "failed"
        http_status = 500
        error_msg = str(e)

    db.log_notification_attempt(
        destination_id=dest["id"],
        rule_id=None,
        event_type="system.email",
        status=status,
        http_status_code=http_status,
        error_message=error_msg,
        payload_dict=payload,
    )
    return success


def send_verification_email(
    email: str,
    target_type: str = "user",
    target_id: str | None = None,
    base_url: str = "https://rover.local",
) -> bool:
    """Dispatches a confirmation email with a 24-hour verification link."""
    token = generate_email_verification_token(email, target_type, target_id)
    confirm_url = build_verification_url(token, base_url=base_url)
    subject = "R.O.V.E.R — Verify Your Email Address"
    message = (
        f"Hello,\n\n"
        f"Please verify your email address for R.O.V.E.R by visiting the link below:\n\n"
        f"{confirm_url}\n\n"
        f"This verification link will expire in 24 hours.\n\n"
        f"If you did not request this email, please disregard it."
    )
    return send_system_email(to_email=email, subject=subject, message=message)


def send_password_reset_email(
    email: str, base_url: str = "https://rover.local"
) -> bool:
    """Dispatches a password reset recovery link valid for 24 hours."""
    token = generate_password_reset_token(email)
    reset_url = build_password_reset_url(token, base_url=base_url)
    subject = "R.O.V.E.R — Password Reset Request"
    message = (
        f"Hello,\n\n"
        f"A password reset was requested for your R.O.V.E.R account ({email}).\n\n"
        f"Click the link below to set a new password:\n\n"
        f"{reset_url}\n\n"
        f"This recovery link will expire in 24 hours. If you did not request a password reset, you can safely ignore this message."
    )
    return send_system_email(to_email=email, subject=subject, message=message)


def send_magic_access_email(email: str, base_url: str = "https://rover.local") -> bool:
    """Dispatches a passwordless magic access link for the subscriptions management portal."""
    token = generate_magic_access_token(email)
    access_url = build_magic_access_url(token, base_url=base_url)
    subject = "R.O.V.E.R — Access Your Subscriptions"
    message = (
        f"Hello,\n\n"
        f"Here is your secure access link for R.O.V.E.R Notification Subscriptions:\n\n"
        f"{access_url}\n\n"
        f"Clicking this link will log you in to manage your notification rules and email preferences.\n"
        f"This access link will expire in 24 hours.\n\n"
        f"If you did not request this link, please disregard this email."
    )
    return send_system_email(to_email=email, subject=subject, message=message)
