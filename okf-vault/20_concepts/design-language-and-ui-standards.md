# Design Language & UI Standards

**Type**: Concept Note
**Domain**: Web Interface, Frontend Architecture, Design System
**Related**: [[notification_system_architecture]], [[user-roles-and-product-permissions]], [[hybrid-identity-rbac-architecture]]

---

## Overview

R.O.V.E.R. implements a standardized, accessible design system built on **Pico CSS v2** (semantic CSS framework). The interface uses dark-mode defaults (`data-theme="dark"`), semantic HTML5 tags, standard Pico CSS modifier classes, and unified color tokens across all 25 template files (`src/rover/templates/*.html`).

---

## 🎨 Component Standards

### 1. HTML Element Conventions

- **Page Layout**: `<main class="container">` wraps all primary views.
- **Card Containers**: `<article>` serves as the standard container for dashboard widgets, scanner reports, and forms.
- **Grids**: `<div class="grid">` handles responsive multi-column layouts.
- **Collapsible Panels**: `<details>` and `<summary>` handle expandable logs, raw JSON results, and quick actions.
- **Modals**: Native `<dialog>` elements handle popup forms (e.g. Add Rule, Test Destination).

### 2. Action Controls & Button Sizing Standards

- **Primary Toolbar CTA**: `height: 36px`, `padding: 0 0.85rem`, `font-size: 0.85rem`, `border-radius: 6px`. Placed first at the left edge of toolbar action groups (e.g. `[+ Create Release]`, `[+ Add Destination]`).
- **Secondary Toolbar Actions**: `role="button" class="outline secondary"`, `height: 36px`. Neutral outline buttons for navigation (`[🕒 Schedules]`, `[🔔 Notifications]`).
- **Destructive Header Actions**: `height: 36px`, red outline (`color: #ef4444`, `border-color: rgba(...)`). Positioned at the far right of action groups, distinct from standard workflows.
- **Compact Table Actions**: `height: 32px`, `padding: 0 0.65rem`, `font-size: 0.8rem` (`Send Test`, `Make Default`).
- **Icon-Only Table Actions**: `height: 32px`, `width: 32px`, `min-width: 32px`, `padding: 0`. Square icon-only button for row settings/edits (`{{ icon('settings', size=16) }}`) with tooltip `title="..."`.
- **Non-Wrapping Standard**: All action controls and badges MUST include `white-space: nowrap; flex-shrink: 0;` to prevent vertical text wrapping.

### 3. Refined Status Pills & Microcopy

- **Title-Case Microcopy**: Status badges use title-case concise labels (`Critical Risk`, `High Risk`, `Medium Risk`, `Low Risk`, `Clean (No Vulnerabilities)`).
- **Disabling Uppercase Transformation**: Override badge uppercase styling (`text-transform: none; font-weight: 600; font-size: 0.8rem;`) to preserve clean geometry.
- **Integrated Iconography (`size=16`)**: Embed `16px` vector icons (`shield-alert`, `shield-check`, `check-circle`, `zap`, `x-circle`, `calendar`) inline with text.

### 4. Table Alignment & Empty States

- **HTML Table Cell Display Rules**: Never set `display: flex` directly on a `<td>` element (overrides `display: table-cell` and causes row "step" / height misalignment). Always keep `<td>` as standard table cell and wrap buttons in an internal `display: inline-flex` container.
- **Empty State Component**: Empty states use a centered layout, circular icon badge (`56px` × `56px`), clear title, concise subtext, and an inline primary CTA button.

### 5. Self-Hosted Lucide Icon System

- **Zero-CDN Architecture**: Vector SVG files stored in `src/rover/static/icons/*.svg` (ISC License FOSS).
- **Jinja2 Global Helper**: Templates call `{{ icon('name', size=18) }}` (`src/rover/icons.py`).
- **Inline Vector Rendering**: SVGs render inline for 0 HTTP requests and inherit CSS theme colors via `stroke: currentColor`.

---

## 🌈 Color Tokens & Severity Palette

| Category | Hex Palette | RGBA Translucent Accent | Usage |
| :--- | :--- | :--- | :--- |
| **Critical / Emergency** | `#ef4444`, `#f87171`, `#dc2626` | `rgba(239, 68, 68, 0.15)` | `CRITICAL` severity, `scan.failed`, error messages. |
| **High Severity** | `#ea580c`, `#f97316` | `rgba(234, 88, 12, 0.15)` | `HIGH` severity vulnerabilities. |
| **Medium / Warning** | `#f59e0b`, `#fbbf24` | `rgba(245, 158, 11, 0.15)` | `MEDIUM` severity, `eol.warning` lead times, unverified badges. |
| **Low / Healthy / Verified**| `#10b981`, `#34d399`, `#22c55e` | `rgba(16, 185, 129, 0.15)` | `LOW` severity, `scan.completed`, deliverability verified badges. |
| **EOL Lifecycle** | `#a855f7`, `#c084fc` | `rgba(168, 85, 247, 0.15)` | `eol.warning` rules, deprecation badges. |
| **Info / System Roles** | `#3b82f6`, `#60a5fa` | `rgba(59, 130, 246, 0.15)` | `system_admin` role badges, active tabs, link buttons. |

---

## 🌌 Theme Variables (Pico CSS Tokens)

- `--pico-background-color`: Base application background (`#0f172a`).
- `--pico-card-background-color`: Surface background for cards and modals (`#1e293b`).
- `--pico-border-color`: Divider lines and container borders (`#334155`).
- `--pico-color`: Primary body text (`#f8fafc`).
- `--pico-muted-color`: Subtitles, timestamps, muted annotations (`#94a3b8`).
- `--pico-primary`: Primary blue accent (`#3b82f6`).

---

## 🪟 Modal Dialog Architecture

1. **HTML5 `<dialog>` Standard**: All modal popups use standard `<dialog>` elements styled by Pico CSS.
2. **Encapsulated Close Button**: Modal headers standard close button: `<button aria-label="Close" rel="prev" onclick="this.closest('dialog').close();"></button>`.
3. **Global Backdrop Dismissal**: Global listener in `base.html` automatically detects clicks outside `<article>` on the backdrop and closes the dialog.
4. **Automated Form State Reset**: Global `'close'` listener automatically resets internal form inputs when modals are dismissed.
5. **Programmatic Global Confirmation (`openGlobalConfirmModal`)**: Reusable helper for destructive confirmation prompts (`openGlobalConfirmModal(options)`) with support for mandatory typing verification (`requireTyping: true`).

