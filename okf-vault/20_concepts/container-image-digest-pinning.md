---
id: "202607261113"
type: Concept
title: Container Image Digest Pinning Policy
description: Immutable sha256 digest pinning policy for container scanner images to prevent supply chain compromise.
created: "2026-07-26T11:13:00Z"
updated: "2026-07-26T11:13:00Z"
tags:
  - security/supply-chain
  - rover/policy
  - docker/pinning
status: stable
stale_after: "2027-01-01"
aliases:
  - Image Digest Pinning
  - SHA256 Pinning Policy
---

# Container Image Digest Pinning Policy

> **Summary**: Policy mandating that all container image references used by security scanners (Trivy, Semgrep, Helm) MUST be pinned directly to immutable `sha256` digests rather than mutable image tags.

## 1. Motivation & Threat Model

Mutable image tags (such as `:latest` or version tags like `:0.69.3`) are not cryptographically fixed. A malicious actor with compromised repository credentials or a hijacked build pipeline can overwrite a published tag with a malicious container image.

### Real-World Supply Chain Incident
This policy directly addresses vulnerabilities such as the **Trivy Ecosystem Supply Chain Compromise** documented in [[ghsa-69fq-xp46-6x23-trivy-supply-chain-advisory|GHSA-69fq-xp46-6x23]]. In supply chain attacks, relying on tags exposes scanner workers to malicious code execution or tampered vulnerability database reporting.

---

## 2. Implementation Standard

1. **Format Specification**:
   All container image configurations MUST use the explicit `image_name@sha256:<hash>` syntax:
   ```toml
   [scanners]
   trivy_image = "aquasec/trivy@sha256:cffe3f5161a47a6823fbd23d985795b3ed72a4c806da4c4df16266c02accdd6f"
   semgrep_image = "semgrep/semgrep@sha256:98c2572fced2474539fd27cab3207ebd8e95e4e7aab4c3b381fdc5e2641d9941"
   helm_image = "alpine/helm@sha256:b97ba4f9b27fe7af16ee3d37e6815783c9d4a51289b6240a9024ec471611ae9b"
   ```

2. **ROVER Configuration Architecture**:
   ROVER reads pinned image references from `config.toml` via `rover.config.get_scanner_image()`. If an image pin is un-set or invalid, execution is blocked safely.

3. **Updating Pinned Images**:
   When upgrading scanner versions:
   - Audit release notes from official upstream vendor repositories.
   - Inspect the cryptographically signed digest (`sha256`).
   - Update `config.toml` with the new digest.

---

## 3. Related Concepts & References
- **Advisory Reference**: [[ghsa-69fq-xp46-6x23-trivy-supply-chain-advisory]]
- **Trivy Scanner Plugin**: [[trivy-scanner-plugin]]
- **Semgrep Scanner Plugin**: [[semgrep-scanner-plugin]]
- **Map of Content**: [[scanners-moc]]
