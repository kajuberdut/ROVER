---
title: Automated Scan Scheduler
description: Configure automated background scan schedules, cron expressions, and execution audit history.
---

R.O.V.E.R. includes an in-process background scan scheduler engine to evaluate products and releases automatically on recurring schedules.

---

## Configuring a Schedule

1. Navigate to your **Product Dashboard** and click **📅 Schedules** in the toolbar.
2. Click **+ Add Schedule**.
3. Fill out the schedule details:
   - **Name**: A descriptive title (e.g. `Nightly Security Audit`).
   - **Frequency / Cron Expression**: Choose a standard preset (`@daily`, `@weekly`, `@monthly`) or enter a custom 5-field cron string (e.g. `0 2 * * *` for 2:00 AM UTC daily).
   - **Target Scope**: Select all releases in the product or bind to a specific release version.
4. Click **Create Schedule**.

---

## Execution Audit Logs & Live Progress

Click **Audit Logs** on any schedule to open the execution history modal:
- **Trigger Timestamp**: Records exact ISO-8601 execution time.
- **Status Badge**: Indicates whether job dispatch succeeded (`success`) or encountered an error (`failed`).
- **Live Job Progress**: Displays real-time scanner completion breakdown (e.g. `⏳ 3/10 completed (2 running, 5 queued)` → `✔ All 10 scans completed`).

---

## Manual Triggering & Pausing

- **⚡ Run**: Manually trigger an immediate background scan run without altering the schedule's recurring timer.
- **Pause / Enable**: Temporarily suspend background evaluation without deleting configuration.
