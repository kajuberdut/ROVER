"""rover/routes/_env.py: Shared Jinja2 environment.

All route modules import ``template_env`` from here so that the
environment (loader, autoescape settings, and custom filters) is
configured exactly once.
"""

import json
import os
from datetime import datetime

import jinja2

template_dir = os.path.join(os.path.dirname(__file__), "..", "templates")
template_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=jinja2.select_autoescape(["html", "xml"]),
)
from typing import Any


def safe_load_json(val: Any) -> Any:
    if val is None:
        return {}
    if isinstance(val, (dict, list)):
        return val
    if isinstance(val, (str, bytes, bytearray)):
        try:
            return json.loads(val)
        except Exception:
            return {}
    return val


template_env.filters["loadjson"] = safe_load_json


def humanize_time(date_val: str | datetime | None) -> str:
    if not date_val:
        return "N/A"
    dt: datetime | None = None
    if isinstance(date_val, datetime):
        dt = date_val
    elif isinstance(date_val, str):
        cleaned = date_val.strip().replace(" ", "T")
        import contextlib

        with contextlib.suppress(Exception):
            dt = datetime.fromisoformat(cleaned)
        if dt is None:
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d"):
                with contextlib.suppress(Exception):
                    dt = datetime.strptime(date_val, fmt)
                    break

    if dt is None:
        return str(date_val)

    from datetime import timezone

    now = datetime.now(timezone.utc) if dt.tzinfo else datetime.now()
    diff = now - dt
    total_seconds = int(diff.total_seconds())

    if total_seconds < 60:
        return "Just now"
    elif total_seconds < 3600:
        mins = total_seconds // 60
        return f"{mins} min{'s' if mins > 1 else ''} ago"
    elif total_seconds < 86400:
        hours = total_seconds // 3600
        return f"{hours} hour{'s' if hours > 1 else ''} ago"
    elif diff.days == 1:
        return "Yesterday"
    else:
        return dt.strftime("%b %d, %Y")


template_env.filters["humanize_time"] = humanize_time


def short_url(url: str | None) -> str:
    if not url:
        return ""
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]
    if "/" in url:
        return url.split("/", 1)[1]
    return url


template_env.filters["short_url"] = short_url


def _get_active_notifications_count() -> int:
    try:
        from rover import db

        return len(db.get_active_admin_notifications())
    except Exception:
        return 0


template_env.globals["get_active_notifications_count"] = _get_active_notifications_count

from rover.icons import render_icon

template_env.globals["icon"] = render_icon
