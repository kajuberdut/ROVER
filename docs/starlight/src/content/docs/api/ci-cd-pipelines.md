---
title: CI/CD Pipeline Ingestion
description: Learn how to integrate GitHub Actions, GitLab CI, and Jenkins pipelines with R.O.V.E.R.
---

Automate container image and artifact tracking directly from your continuous integration pipelines.

---

## `POST /api/ci/image-metadata`

Send container image digests, git commit SHAs, image tags, and pipeline execution URLs to R.O.V.E.R. upon container build completion.

### Request Body Schema

```json
{
  "image_hash": "sha256:7f83b1657ff1...def",
  "repo_uri": "https://github.com/my-org/my-app.git",
  "commit_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
  "image_tags": ["latest", "v1.4.0"],
  "ci_job_url": "https://github.com/my-org/my-app/actions/runs/12345678",
  "metadata": {
    "builder": "github-actions",
    "runner_os": "ubuntu-22.04"
  }
}
```

---

## GitHub Actions Example

```yaml
name: Build & Register Image Metadata

on:
  push:
    branches: [ main ]

jobs:
  build-and-ingest:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build Docker Image
        id: build
        run: |
          docker build -t my-repo/my-app:${{ github.sha }} .
          IMAGE_DIGEST=$(docker inspect --format='{{index .RepoDigests 0}}' my-repo/my-app:${{ github.sha }})
          echo "digest=$IMAGE_DIGEST" >> $GITHUB_OUTPUT

      - name: Send Metadata to R.O.V.E.R.
        run: |
          curl -X POST "https://rover.local/api/ci/image-metadata" \
            -H "Authorization: Bearer ${{ secrets.ROVER_API_TOKEN }}" \
            -H "Content-Type: application/json" \
            -d '{
              "image_hash": "'"${{ steps.build.outputs.digest }}"'",
              "repo_uri": "https://github.com/'"${{ github.repository }}"'.git",
              "commit_hash": "'"${{ github.sha }}"'",
              "image_tags": ["latest"],
              "ci_job_url": "'"${{ github.server_url }}/${{ github.repository }}/actions/runs/${{ github.run_id }}"'"
            }'
```
