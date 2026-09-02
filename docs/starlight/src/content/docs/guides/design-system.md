---
title: Design System & UI Standards
description: Comprehensive reference guide for ROVER UI design language, Pico CSS classes, components, color tokens, and layout guidelines.
---

This guide defines the official design language, component conventions, Pico CSS framework extensions, and color system for the R.O.V.E.R. platform. All web interface templates (`src/rover/templates/*.html`) follow these standards to ensure visual consistency, accessibility, and clean responsive layout.

---

## 🎨 Design System Principles

1. **Semantic HTML First**: Prefer standard HTML5 elements (`<article>`, `<header>`, `<footer>`, `<nav>`, `<aside>`, `<dialog>`, `<details>`, `<summary>`, `<fieldset>`, `<grid>`) over generic unstyled `<div>` elements.
2. **Pico CSS Framework**: Built on top of **Pico CSS v2** (`data-theme="dark"` by default). Use Pico CSS semantic selectors and utility classes rather than custom CSS frameworks.
3. **Consistent Interactive Elements**: Hyperlinks that trigger actions must use `role="button"` combined with appropriate modifier classes (`primary`, `secondary`, `contrast`, `outline`).
4. **Unified Color Semantics**: Status indicators, vulnerability severity badges, and notification event pills strictly adhere to standardized color tokens.

---

## 🧩 HTML Elements & Pico CSS Features

### Structural Elements

| HTML Element | Purpose & Usage in ROVER |
| :--- | :--- |
| `<main class="container">` | Top-level content wrapper enforcing responsive max-width and horizontal margins. |
| `<article>` | Primary container card for dashboards, scan reports, form blocks, and data tables. |
| `<header>` & `<footer>` | Top header bar and bottom footer area inside cards or application pages. |
| `<div class="grid">` | Pico CSS auto-responsive grid layout for side-by-side columns. |
| `<dialog>` | Native modal dialog windows (e.g. Add Rule, Test Destination, Invitation Modals). |
| `<details>` & `<summary>` | Collapsible accordion sections (e.g., Quick Scan panel, Raw Scan JSON output). |

### Interactive Buttons & Action Controls

Buttons and action links adhere to standardized heights, compact padding, and flexbox alignment to maintain a refined visual presentation across toolbars, forms, and data tables:

```html
<!-- Primary CTA Header Button (Height: 36px, Lucide Icon) -->
<button type="button" style="height: 36px; padding: 0 0.85rem; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 0.4rem; margin-bottom: 0; border-radius: 6px; white-space: nowrap;">
    {{ icon('plus', size=16) }} Create Release
</button>

<!-- Secondary Neutral Toolbar Link (Height: 36px) -->
<a href="/schedules" role="button" class="outline secondary" style="height: 36px; padding: 0 0.85rem; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 0.4rem; margin-bottom: 0; border-radius: 6px; white-space: nowrap;">
    {{ icon('clock', size=16) }} Schedules
</a>

<!-- Icon-Only Table Row Action Button (32px x 32px Square) -->
<button onclick="openEditModal()" class="outline" style="height: 32px; width: 32px; min-width: 32px; padding: 0; margin-bottom: 0; display: inline-flex; align-items: center; justify-content: center; border-radius: 6px; flex-shrink: 0;" title="Edit Settings">
    {{ icon('settings', size=16) }}
</button>

<!-- Text-Only Compact Table Button (Height: 32px) -->
<button onclick="testPing()" class="outline" style="height: 32px; padding: 0 0.65rem; font-size: 0.8rem; margin-bottom: 0; display: inline-flex; align-items: center; justify-content: center; border-radius: 6px; white-space: nowrap; flex-shrink: 0;">
    Send Test
</button>

<!-- Destructive Action Button (Far Right, Red Outline) -->
<button type="button" class="outline" style="height: 36px; padding: 0 0.85rem; font-size: 0.85rem; display: inline-flex; align-items: center; gap: 0.4rem; margin-bottom: 0; border-radius: 6px; color: #ef4444; border-color: rgba(239, 68, 68, 0.4); white-space: nowrap;">
    {{ icon('trash-2', size=16) }} Delete Product
</button>
```

| Component Category | Dimension & Syntax Standards | Visual Guidelines |
| :--- | :--- | :--- |
| **Primary Toolbar CTA** | `height: 36px`, `padding: 0 0.85rem`, `font-size: 0.85rem`, `border-radius: 6px` | Positioned first at the left of header action groups (`+ Create Release`, `+ Add Destination`). |
| **Secondary Toolbar Actions** | `role="button" class="outline secondary"`, `height: 36px` | Neutral outline buttons for navigation links (`Schedules`, `Notifications`, `Permissions`). |
| **Destructive Header Action** | `height: 36px`, `color: #ef4444`, `border-color: rgba(...)` | Positioned at the far right of action groups, distinct from standard workflows. |
| **Compact Table Action** | `height: 32px`, `padding: 0 0.65rem`, `font-size: 0.8rem` | Compact text buttons inside table row cells (`Send Test`, `Make Default`). |
| **Icon-Only Action** | `height: 32px`, `width: 32px`, `min-width: 32px`, `padding: 0` | Square icon-only button for row settings/edits (`{{ icon('settings', size=16) }}`) with tooltip `title="..."`. |
| **Non-Wrapping Rule** | `white-space: nowrap; flex-shrink: 0;` | Mandatory on all buttons to prevent multi-word button labels from wrapping vertically. |

---

## 🎨 Self-Hosted FOSS Vector Icon System (Lucide Icons)

ROVER uses **Lucide Icons** (ISC License, 100% Permissive Open Source) for crisp, professional UI iconography across the application interface and documentation.

### 1. Zero-CDN Self-Hosted Architecture
- Icons are stored as local vector SVG files in `src/rover/static/icons/*.svg`.
- No external network or CDN calls are made. ROVER operates 100% self-contained in air-gapped environments.
- Jinja templates embed icons inline using the `{{ icon('name', size=18) }}` Jinja global helper (`src/rover/icons.py`).
- Inline SVG vectors inherit CSS text colors (`stroke: currentColor`) for seamless theme dark-mode adaptability.

### 2. Icon Usage in Templates

```jinja
<!-- Default 18px Icon -->
{{ icon('shield') }} Security Overview

<!-- Custom Size (e.g. 24px Header Icon) -->
{{ icon('rocket', size=24) }} Launch Scan

<!-- Icon with Custom CSS Class -->
{{ icon('alert-triangle', class_name='text-danger') }} Warning
```

### 3. Core Icon Set Reference

| Icon Name | Symbol Code | Application Usage |
| :--- | :--- | :--- |
| `shield` | `{{ icon('shield') }}` | ROVER brand, posture overview, security. |
| `rocket` | `{{ icon('rocket') }}` | Scan execution, activation, deployment. |
| `settings` | `{{ icon('settings') }}` | System configuration, edit settings. |
| `users` | `{{ icon('users') }}` | User management, team members, user dropdown. |
| `key` / `lock` | `{{ icon('key') }}` / `{{ icon('lock') }}` | API tokens, credential vault, authentication. |
| `bell` / `radio` | `{{ icon('bell') }}` / `{{ icon('radio') }}` | Alert subscriptions, notification destinations. |
| `book-open` | `{{ icon('book-open') }}` | Documentation and user guides. |
| `alert-triangle` | `{{ icon('alert-triangle') }}` | System alerts, errors, critical warnings. |
| `check-circle` | `{{ icon('check-circle') }}` | Success state, verified email, scan passed. |
| `clock` / `calendar` | `{{ icon('clock') }}` / `{{ icon('calendar') }}` | Scheduled scan triggers, releases. |

---

## 🏷️ Custom ROVER Utility Classes & Status Badges

| Class Name | Description & Usage |
| :--- | :--- |
| `.role-badge` | Compact pill badge for system roles (`system_admin`, `viewer`), scopes, risk status, and notification rules. |
| `.status-pill` | Status indicator badge for scanner execution state (`running`, `completed`, `failed`, `queued`). |
| `.finding-badge` | Count badge for vulnerability severity levels (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `UNKNOWN`). |
| `.breadcrumb-row` | Top breadcrumb navigation wrapper. |
| `.breadcrumb-sep` | Breadcrumb chevron separator (`›`). |
| `.site-header` | Sticky top navigation bar. |
| `.user-menu-dropdown` | User profile avatar dropdown menu. |
| `.sticky-table` | Data table container with fixed headers for scan report listings. |

### Status Pill & Microcopy Standards

Status indicators and risk badges adhere to clean title-case microcopy, explicit non-wrapping, and inline vector icons:

```html
<!-- Refined Status Pill Badge (Size 16 Icon, Title-Case Text, Non-Wrapping) -->
<span class="role-badge" style="background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); font-size: 0.8rem; font-weight: 600; text-transform: none; white-space: nowrap; padding: 0.3rem 0.65rem; border-radius: 6px; display: inline-flex; align-items: center; gap: 0.45rem;">
    {{ icon('shield-alert', size=16) }} Critical Risk
</span>
```

1. **Title-Case Microcopy**: Use concise title-case labels (`Critical Risk`, `High Risk`, `Medium Risk`, `Low Risk`, `Clean (No Vulnerabilities)`). Avoid long all-caps text.
2. **Disabling Uppercase Transformation**: Override badge uppercase styling (`text-transform: none; font-weight: 600; font-size: 0.8rem;`) to preserve clean geometry.
3. **Integrated Iconography (`size=16`)**: Embed `16px` vector icons (`shield-alert`, `shield-check`, `check-circle`, `zap`, `x-circle`, `calendar`) inline with gap spacing (`gap: 0.45rem`).
4. **Mandatory Non-Wrapping**: Declare `white-space: nowrap;` on all status badges to ensure pills remain single-line across grid cards and tables.

---

## 📐 Layout, Table Alignment & Empty State Conventions

When creating or updating templates in `src/rover/templates/`:

1. **HTML Table Cell Display Rules (`<td>` vs Flexbox)**:
   - **Rule**: Never set `display: flex` directly on a `<td>` element! Doing so overrides default `display: table-cell`, detaching the cell from the HTML table layout grid and producing vertical height misalignment ("step" / notch artifacts).
   - **Correct Pattern**: Keep `<td>` as standard table-cell (`<td style="text-align: right; vertical-align: middle; white-space: nowrap;">`) and wrap action buttons in an internal flex container `<div style="display: inline-flex; gap: 0.5rem; justify-content: flex-end; align-items: center;">`.

2. **Table Header & Data Cell Non-Wrapping**:
   - Apply `white-space: nowrap;` across table headers (`<th>`) and timestamp / cell text (`<td>`) to ensure compact, horizontal table rows.

3. **Standard Empty State Pattern**:
   - When a table or card grid contains 0 items, render a styled empty-state box instead of plain text:
   ```html
   <div style="grid-column: 1 / -1; text-align: center; padding: 3.5rem 1.5rem; color: var(--pico-muted-color); display: flex; flex-direction: column; align-items: center; justify-content: center; gap: 0.75rem; background: var(--pico-card-background-color); border: 1px solid var(--pico-border-color); border-radius: 8px;">
       <div style="background: rgba(255, 255, 255, 0.05); border: 1px solid var(--pico-border-color); border-radius: 50%; width: 56px; height: 56px; display: flex; align-items: center; justify-content: center; color: var(--pico-muted-color);">
           {{ icon('box', size=26) }}
       </div>
       <div style="font-weight: 600; font-size: 1.05rem; color: var(--pico-color);">No Items Found</div>
       <p style="margin: 0; font-size: 0.85rem; max-width: 440px; color: var(--pico-muted-color);">
           Descriptive explanation text explaining what to do next.
       </p>
       <button type="button" style="width: auto; font-size: 0.8rem; padding: 0.35rem 0.85rem; margin-top: 0.5rem; display: inline-flex; align-items: center; gap: 0.35rem; border-radius: 6px;">
           {{ icon('plus', size=14) }} Create Item
       </button>
   </div>
   ```

4. **Breadcrumbs**: Include a standard breadcrumb block at the top of content blocks:
   ```html
   {% block breadcrumb %}
   <a href="/">Dashboard</a>
   <span class="breadcrumb-sep">›</span>
   <span>Notification Subscriptions</span>
   {% endblock %}
   ```

2. **Card Headers**: Place title and subtitle text in standard flex header layouts:
   ```html
   <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem;">
       <div>
           <h2>Title</h2>
           <p style="color: var(--pico-muted-color); font-size: 0.9rem;">Description text...</p>
       </div>
       <div>
           <a href="/target" role="button" class="secondary outline">Action</a>
       </div>
   </div>
   ```

3. **Forms & Modals**: Wrap form controls inside native `<fieldset>` and `<label>` tags provided by Pico CSS for automatic vertical alignment.

---

## 🪟 Modal Dialog Architecture & Design Standards

ROVER utilizes native HTML5 `<dialog>` elements integrated with Pico CSS modal styling and encapsulated JavaScript handlers.

### 1. Form & Content Modals (`<dialog>`)

Custom content modals (e.g. Create Product, Create Release, Add Asset, Create Notification Rule, Generate Token) follow a unified, self-contained structure:

```html
<dialog id="create-rule-modal">
    <article style="max-width: 600px;">
        <header>
            <button aria-label="Close" rel="prev" onclick="this.closest('dialog').close();"></button>
            <strong>Add Notification Rule</strong>
        </header>
        <form action="/api/notifications/rules" method="POST" style="margin-bottom: 0;">
            <fieldset>
                <label>Rule Name
                    <input type="text" name="name" required placeholder="e.g. Production Security Alerts">
                </label>
                <!-- Additional form fields -->
                <button type="submit">Save Rule</button>
            </fieldset>
        </form>
    </article>
</dialog>
```

#### Key Rules for Custom Modals:
- **Encapsulated Close Button**: Header close buttons MUST use `onclick="this.closest('dialog').close();"` rather than hardcoded element IDs.
- **Card Wrapper**: Direct child of `<dialog>` MUST be an `<article>` to enforce card padding, dark-mode background, and backdrop bounds.
- **Global Backdrop Dismissal**: Global listener in `base.html` automatically detects clicks outside `<article>` on the backdrop and closes the dialog.
- **Automatic Form Reset**: Global listener in `base.html` catches the dialog `'close'` event and clears form fields so modals open with fresh state.

---

### 2. Programmatic Confirmation Modal (`openGlobalConfirmModal`)

For destructive or critical confirmation steps (Delete Product, Delete Release, Delete Asset, Revoke API Token), ROVER provides a centralized programmatic modal (`#global-confirm-modal` in `base.html`).

#### Programmatic Invocation:

```javascript
// Simple Confirmation
openGlobalConfirmModal({
    title: 'Delete Asset',
    message: 'Are you sure you want to remove asset <strong>v1.2.0</strong> from this release?',
    actionUrl: '/releases/rel_123/assets/ast_456/delete',
    buttonText: 'Delete Asset'
});

// Destructive Action with Mandatory Verification Typing
openGlobalConfirmModal({
    title: 'Delete Product',
    message: 'This will permanently purge this product and all associated releases and scan history.',
    actionUrl: '/products/prod_123/delete',
    buttonText: 'Permanently Delete',
    requireTyping: true,
    expectedText: 'core-api-service'
});
```

#### Modal Options Schema:

| Property | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `title` | `string` | `'Confirm Action'` | Header text displayed in red highlight. |
| `message` | `string` | `'This action is irreversible.'` | HTML message body describing consequences. |
| `actionUrl` | `string` | *(Required)* | Form submission target endpoint URL. |
| `actionValue` | `string` | `'delete'` | Value assigned to hidden `name="action"` field. |
| `buttonText` | `string` | `'Confirm'` | Label for the red submit button. |
| `requireTyping` | `boolean` | `false` | When `true`, disables the submit button until the user types `expectedText`. |
| `expectedText` | `string` | `'I understand'` | Exact text the user must type to unlock confirmation. |

