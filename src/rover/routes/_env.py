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
template_env.filters["loadjson"] = json.loads


def humanize_time(date_str: str | None) -> str:
    if not date_str:
        return "N/A"
    try:
        dt = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
        now = datetime.now()
        diff = now - dt
        if diff.days == 0:
            if diff.seconds < 60:
                return "Just now"
            elif diff.seconds < 3600:
                mins = diff.seconds // 60
                return f"{mins} min{'s' if mins > 1 else ''} ago"
            else:
                hours = diff.seconds // 3600
                return f"{hours} hour{'s' if hours > 1 else ''} ago"
        elif diff.days == 1:
            return "Yesterday"
        else:
            return dt.strftime("%b %d, %Y")
    except Exception:
        return date_str


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
