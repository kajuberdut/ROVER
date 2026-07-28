---
title: Quickstart Guide
description: Learn how to set up, launch, and run your first vulnerability evaluation scan on R.O.V.E.R.
---

This guide walks you through setting up R.O.V.E.R. locally using `poe` and running your first multi-scanner evaluation.

---

## Prerequisites

- **Docker & Docker Compose** (v2.20+)
- **Python 3.12+** with `uv` package manager installed
- **Poe the Poet** (`poe`) task runner

---

## 1. Environment Setup

Run the first-time setup command to generate TLS certificates, secret keys, and initialize the OpenBao Vault engine:

```bash
poe setup
```

---

## 2. Launching the Service Stack

Start the R.O.V.E.R. container stack:

```bash
poe up
```

Check service health and process status at any time:

```bash
poe status
```

Access the web dashboard in your browser at `https://rover.local` (or `http://localhost:8000`).

---

## Local Domain Setup & Development Use

For local development, testing, and getting started, R.O.V.E.R. routes local traffic through `https://rover.local` (main dashboard) and `https://auth.rover.local` (Authelia single sign-on).

:::note[Production vs Local Use]
Adding `rover.local` to your local `hosts` file is only required for local development and getting started. When hosting R.O.V.E.R. in a production environment behind a public HTTPS domain, configure your organization's DNS records and reverse proxy instead.
:::

When you run `poe setup`, the setup process automatically checks your system's `hosts` file (`/etc/hosts` on Linux/macOS or `C:\Windows\System32\drivers\etc\hosts` on Windows). If missing, `poe setup` will instruct you to add the following entry:

```text
127.0.0.1  rover.local auth.rover.local
```

---

## 3. Creating Your First Release Scan

1. **Create a Product**: Navigate to the home dashboard and click **+ New Product**. Enter a name (e.g. `My Service`).
2. **Add a Release**: Open the product dashboard and click **+ New Release** (e.g. `v1.0.0`).
3. **Add Target Assets**:
   - Add a repository URI (e.g. `https://github.com/example/demo.git`).
   - Add a container image (e.g. `python:3.12-slim`).
4. **Trigger Evaluation**: Click **⚡ Run All Scanners**.
5. **Monitor Progress**: Watch real-time scanner widgets progress from `Queued` → `Running` → `Completed`.
6. **Inspect Reports**: Click **View Report** to analyze findings in the unified multi-scanner report viewer.
