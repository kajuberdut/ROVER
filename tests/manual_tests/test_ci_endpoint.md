# Manual Test: CI Pipeline Metadata Endpoint

These tests cover the `POST /api/ci/image-metadata` endpoint used by CI pipelines to securely publish image build metadata. Run these tests after any changes to `scan_queue.py` (specifically `add_ci_image_metadata`), `app.py` (`CiImageMetadataResource`), or the `permissions.py` API token hooks.

**Prerequisites**
- ROVER is running locally (`docker compose up -d`)
- You have generated a Write API token (`rover_w_...`) via the ROVER UI (`/settings/tokens`).
- You have generated a Read-Only API token (`rover_r_...`) via the ROVER UI (`/settings/tokens`).

*Note: Replace `$WRITE_TOKEN` and `$READ_TOKEN` in the examples below with your actual generated tokens.*

---

## 1. Successful Data Ingestion

Tests the happy path where a CI pipeline successfully authenticates and publishes metadata for a new image.

### Steps

1. Execute the following `curl` command to post metadata:
   ```bash
   curl -s -k -L -X POST "https://localhost/api/ci/image-metadata" \
        -H "Authorization: Bearer $WRITE_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
              "image_hash": "sha256:1234567890abcdef", 
              "repo_uri": "github.com/my-org/my-repo", 
              "commit_hash": "abcde12345", 
              "metadata": {"build_agent": "linux-amd64", "duration": "45s"}, 
              "image_tags": ["latest", "v1.2.3"], 
              "ci_job_url": "https://ci.local/job/1"
            }'
   ```

### Expected

- The endpoint returns an `HTTP 201 Created` (or `200 OK`) status code.
- The JSON response is:
  ```json
  {"status": "ok"}
  ```

---

## 2. Collision Handling (Matching Repo/Commit)

Tests that if a CI pipeline re-runs or publishes the exact same `image_hash`, the system allows the `metadata_json`, `image_tags`, and `ci_job_url` to be overwritten, provided the source repository and commit hash match.

### Steps

1. Execute the following `curl` command using the exact same `image_hash`, `repo_uri`, and `commit_hash` as Test 1, but with updated metadata/tags:
   ```bash
   curl -s -k -L -X POST "https://localhost/api/ci/image-metadata" \
        -H "Authorization: Bearer $WRITE_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
              "image_hash": "sha256:1234567890abcdef", 
              "repo_uri": "github.com/my-org/my-repo", 
              "commit_hash": "abcde12345", 
              "metadata": {"build_agent": "linux-amd64", "duration": "90s", "retried": true}, 
              "image_tags": ["latest", "v1.2.3", "stable"], 
              "ci_job_url": "https://ci.local/job/2"
            }'
   ```

### Expected

- The endpoint returns `{"status": "ok"}`.
- Internally, the database record updates the dynamic fields without error.

---

## 3. Collision Handling (Mismatched Repo/Commit)

Tests that the system actively rejects metadata overwrites if an `image_hash` collides with an existing record, but originates from a different repository or commit hash.

### Steps

1. Execute the following `curl` command using the exact same `image_hash` as Test 1, but intentionally change the `repo_uri`:
   ```bash
   curl -s -k -L -X POST "https://localhost/api/ci/image-metadata" \
        -H "Authorization: Bearer $WRITE_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
              "image_hash": "sha256:1234567890abcdef", 
              "repo_uri": "github.com/different-org/rogue-repo", 
              "commit_hash": "abcde12345", 
              "metadata": {"malicious_payload": true}, 
              "image_tags": ["latest"], 
              "ci_job_url": "https://ci.local/job/3"
            }'
   ```

### Expected

- The endpoint returns an `HTTP 409 Conflict` status code.
- The JSON response is:
  ```json
  {"error": "Image metadata for this hash already exists."}
  ```

---

## 4. Authorization Rejection (Read-Only Token)

Tests that the system actively rejects write operations when authenticated with a Read-Only API token, preventing unauthorized data injection.

### Steps

1. Execute the following `curl` command using a completely unique `image_hash`, but authenticate using your `$READ_TOKEN`:
   ```bash
   curl -s -k -L -X POST "https://localhost/api/ci/image-metadata" \
        -H "Authorization: Bearer $READ_TOKEN" \
        -H "Content-Type: application/json" \
        -d '{
              "image_hash": "sha256:readonly123", 
              "repo_uri": "github.com/my-org/my-repo", 
              "commit_hash": "abcde12345", 
              "metadata": {}, 
              "image_tags": [], 
              "ci_job_url": ""
            }'
   ```

### Expected

- The endpoint returns an `HTTP 403 Forbidden` status code.
- The JSON response is:
  ```json
  {"title": "403 Forbidden", "description": "This endpoint requires an API token with write permissions."}
  ```
