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

### 2. Action Controls & Buttons

Hyperlinks acting as action controls must use explicit `role="button"` combined with modifier classes:

- **Primary Action**: `<button>` or `<button class="primary">` (e.g., Submit, Create Product).
- **Secondary Action**: `<a href="..." role="button" class="secondary">` (e.g., View Details, Cancel).
- **Outline Action**: `<a href="..." role="button" class="secondary outline">` (e.g., Manage System Destinations).
- **High-Contrast Action**: `<a href="..." role="button" class="contrast">` (e.g., Log In).

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
