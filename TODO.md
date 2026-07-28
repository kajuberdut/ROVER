# R.O.V.E.R. Project TODOs & Feature Roadmap

## Scanner & Credential Vault Features

- [x] **Single Asset Re-run (Per-Widget Trigger)**
  - **Feature**: Allow users to click a **⚡ Scan** button on an individual scanner widget (Trivy, Semgrep, or Snyk) or asset row to re-run scans for a single release asset without re-scanning all assets in the release.
  - **Tasks**:
    1. Add single asset scan API endpoint (`POST /api/assets/{id}/scans?scanner=...`). ✅
    2. Add UI button trigger on scanner status widgets in `release_assets_table.html`. ✅
    3. Update Starlight documentation (`docs/starlight/src/content/docs/guides/scanners.md`). ✅

- [ ] **Git SSH Keys (OpenBao Credential Type)**
  - **Feature**: Support storing and injecting private SSH deploy keys in OpenBao Vault for cloning private Git repositories during Semgrep and Snyk scans.
  - **Tasks**:
    1. Add `ssh_key` credential schema and OpenBao storage handler in `src/rover/vault.py`.
    2. Update UI credential creation modal in `src/rover/templates/admin_credentials.html`.
    3. Inject SSH private keys into git worker process environments (`GIT_SSH_COMMAND`).
    4. Update Starlight documentation (`docs/starlight/src/content/docs/guides/vault-credentials.md`).
