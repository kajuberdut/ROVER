# Changelog

All notable changes to the R.O.V.E.R project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Multi-Scanner Architecture & Parallel Execution**: Added parallel multi-process scanning engine (`Trivy`, `Semgrep`, `Snyk`) that executes scanner containers concurrently for faster release evaluations.
- **Snyk Security Scanner Integration**: Integrated Snyk Security CLI scanner for open-source dependency vulnerability detection and container analysis.
- **OpenBao Credential Vault**: Integrated OpenBao Vault for securely storing and managing scanner API tokens, registry credentials, and private Git SSH keys.
- **Per-Asset Scanner Widgets & Execution Time Tracking**: Redesigned the Release Assets view with dedicated per-scanner widgets, real-time progress bars, and historical duration tracking (`"14s (avg: 5s)"`).
- **Unified Report Viewer & Deep-Linking**: Added unified multi-scanner report views with direct tab navigation (`?tab=snyk`, `?tab=semgrep`, `?tab=trivy`) and cross-linked container-to-repository vulnerability views.

