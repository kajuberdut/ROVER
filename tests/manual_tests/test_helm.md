# Manual Test: Helm Import & Source Link Flow

These tests cover the Helm chart discovery/import workflow and the "Link Source
Repository" modal. Run them after any change to `scanner.py`, `app.py`,
`scan_queue.py`, or the release dashboard templates.

**Prerequisites**
- ROVER is running locally (`docker compose up -d`)
- You are logged in as an admin or product_owner
- At least one Product exists; create one if needed via the dashboard

---

## 1. OCI Helm Chart Import

Tests `fetch_helm_chart_versions` (OCI path) and `run_helm_ingestion` (OCI
`helm template` command).

### Steps

1. Navigate to a Product page and click **Add Release**.
2. In the **Create Release** modal, select the **Import Helm Chart** tab.
3. In the **Helm Repository URL** field enter:
   ```
   oci://registry-1.docker.io/bitnamicharts/nginx
   ```
4. Click **Fetch Charts**.

### Expected

- Both dropdowns populate within ~30 seconds (container pull on first run).
- **Chart Name** shows `nginx`.
- **Chart Version** shows a semver string (e.g. `22.6.10`).
- No browser alert or console error.

### Then

5. Leave the defaults selected and click **Import & Scan**.
6. You should be redirected to the new Release page.
7. The **Release Assets** table should list one or more container images
   extracted from the chart (e.g. `registry-1.docker.io/bitnami/nginx:latest`).

### Expected

- Assets appear within a few seconds.
- Each image row shows **Queued** or **Running** scan status, progressing to
  **Completed** once Trivy finishes.
- No `helm_ingest_failed` error banner on the product page.

---

## 2. HTTP Helm Repo Import (regression)

Tests `fetch_helm_chart_versions` (HTTP path) — ensures the OCI change did not
break standard repo imports.

### Steps

1. Repeat the steps above using an HTTP URL instead:
   ```
   https://charts.bitnami.com/bitnami
   ```
2. Click **Fetch Charts**.

### Expected

- **Chart Name** dropdown lists many charts (e.g. `nginx`, `postgresql`, …).
- **Chart Version** dropdown populates with multiple semver entries when a chart
  is selected.
- Selecting a chart and clicking **Import & Scan** succeeds as in test 1.

---

## 3. Link Source Repository — Happy Path

Tests the async modal UX: spinner, success toast, live table update.

### Setup

- Use a Release that contains a container image asset showing the
  **⚠ Missing Source Link** warning and a **Link** button.

### Steps

1. Click the **Link** button next to an image asset.
2. The **Link Source Repository** modal opens.
3. Enter a valid public repository URL, e.g.:
   ```
   https://github.com/nginx/nginx
   ```
4. In **Git Ref (Optional)** enter a branch name, e.g.:
   ```
   master
   ```
5. Click **Link and Scan**.

### Expected (in order)

- Button text changes to **Linking…** with a spinner; all fields disabled.
- Modal closes automatically on success.
- A green toast notification appears at the bottom of the screen:
  > ✓ Scan enqueued — results will appear shortly
- Toast disappears after ~4 seconds.
- The image row in **Release Assets** updates within 3 seconds: the
  **⚠ Missing Source Link** warning is replaced by a 🔗 link showing the
  repository URL.
- No page reload occurs.

---

## 4. Link Source Repository — Commit Hash Ref

Tests the two-step `git clone` + `git checkout` path for exact commit hashes.

### Steps

1. Repeat test 3, but in **Git Ref** enter a 7-character hex commit hash, e.g.:
   ```
   9b958b0
   ```

### Expected

- Same success flow as test 3.
- In the container logs (`docker logs rover-web-1`) you should see:
  ```
  INFO:rover.scanner:Checked out commit 9b958b0 in volume rover-semgrep-clone-...
  ```
- **No** error like `fatal: Remote branch 9b958b0 not found in upstream origin`.

---

## 5. Link Source Repository — Validation Error

Tests that the modal stays open and shows an actionable error on failure.

### Steps

1. Open the **Link Source Repository** modal on any image asset.
2. Clear the URL field completely (or enter a non-URL string).
3. Attempt to submit.

### Expected

- Browser's native `required` validation prevents submit if the field is empty.
- If you bypass this (e.g. via DevTools), the modal should display a red
  inline error banner **inside** the modal without closing it:
  > ⚠ source_repo_url is required.
- The **Link and Scan** button returns to its normal state.
- The modal remains open so the user can correct the input.

---

## 6. Trivy Scan — Architecture Check

Confirms the pinned Trivy image (`v0.69.3`) runs correctly on `linux/amd64`.

### Steps

1. On any Release with a container image asset, click **Scan** (or trigger a
   scan via the release page).
2. Watch the **Latest Scan Status** column.

### Expected

- Status progresses: **Queued → Running → Completed**.
- No `exec format error` in `docker logs rover-web-1`.
- Clicking **View Report** shows vulnerability data (or a clean result).

---

## Notes

- First runs involving `alpine/helm` or `aquasec/trivy` will take longer due to
  image pulls; subsequent runs use the Docker layer cache.
- Semgrep scans on large repos (e.g. `nginx/nginx`) can take several minutes.
  Check `docker logs rover-web-1` for progress.
- To reset test state, delete the release/product via the admin UI and recreate.
