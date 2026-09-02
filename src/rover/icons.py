"""rover/icons.py: Local FOSS Lucide SVG icon renderer for Jinja templates."""

import os
from functools import lru_cache

from markupsafe import Markup

ICONS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "static", "icons"))


@lru_cache(maxsize=128)
def _load_svg(name: str) -> str:
    fpath = os.path.join(ICONS_DIR, f"{name}.svg")
    if not os.path.isfile(fpath):
        # Fallback SVG if icon file missing
        return '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="lucide-icon"><circle cx="12" cy="12" r="10"/></svg>'
    with open(fpath, "r", encoding="utf-8") as f:
        return f.read().strip()


def render_icon(name: str, size: int = 18, class_name: str = "") -> Markup:
    """Render a local Lucide SVG icon inline for zero network requests."""
    svg = _load_svg(name)
    css_class = f"lucide-icon {class_name}".strip()

    # Replace default width/height and add responsive styling
    svg = svg.replace('width="24"', f'width="{size}"', 1)
    svg = svg.replace('height="24"', f'height="{size}"', 1)
    if 'class="' in svg:
        svg = svg.replace('class="', f'class="{css_class} ', 1)
    else:
        svg = svg.replace("<svg ", f'<svg class="{css_class}" ', 1)

    return Markup(svg)  # noqa: S704
