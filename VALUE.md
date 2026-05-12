# R.O.V.E.R — Value Assessment

A concise reference for engineering and security teams evaluating ROVER against alternatives.

---

## Strengths

**Scheduled, automated scanning**
Scans run on a defined cadence without CI pipeline involvement. Vulnerabilities introduced between releases — through dependency database updates or new CVE disclosures — are caught proactively, not only when code changes.

**Helm-native release tracking**
ROVER sources version information directly from Helm chart repositories. Teams do not need to manually register images or repositories when a new chart version is published — the version history is discovered and tracked automatically.

**Role-based access control**
A clear RBAC model separates who can define products and releases from who can view results. Security teams retain oversight while product teams retain autonomy over their own release definitions.

**Tool abstraction**
ROVER presents a single interface regardless of which scanner produced a finding. Pipelines integrate with ROVER rather than with Trivy, Semgrep, or Snyk individually — removing per-tool integration points that must be maintained, secured, and updated separately.

**Company-wide single source of truth**
All vulnerability and end-of-life data lives in one queryable location. Cross-product reporting, organisation-wide severity trending, and compliance evidence no longer require aggregating outputs from disparate tools or spreadsheets.

**Free and permissively licensed**
No per-seat fees, no per-scan quotas, no vendor contracts. ROVER can be adopted, modified, and redistributed freely. The full source is auditable by your own security team.

**Data sovereignty**
Scan results, credential secrets, and software inventory never leave your infrastructure. Particularly relevant for organisations with air-gapped environments, regulated industries, or contractual data residency obligations.

---

## Tradeoffs

**Single maintainer**
There is no SLA, no support contract, and no guaranteed cadence for bug fixes or security patches. Organisations adopting ROVER accept operational risk proportional to their dependency on it.

**Third-party tool coupling**
ROVER's value depends on having tools like Trivy (CVE), Semgrep (SAST), the endoflife.date API, and Snyk (CVE, SAST, licensing). Breaking changes in any upstream tool's output format, licensing terms, or availability will require ROVER changes.

**Operational burden**
Self-hosting requires your team to manage backups, availability monitoring, upgrades, and TLS certificate renewal for the ROVER instance itself. Commercial alternatives include these as a managed service.

**Single-instance architecture**
The current SQLite-backed design has no high-availability or horizontal scaling story. Failure of the host means loss of scan scheduling until it is restored.

**Feature gap vs. commercial tools**
Commercial platforms (Snyk, Wiz, Orca) offer features ROVER does not yet have: reachability analysis, cloud posture management, runtime threat detection, developer IDE plugins, and dedicated support. The ROVER roadmap closes some of this gap but not all of it.

---

## Contextual (Neither Pro Nor Con)

**Reduced pipeline attack surface — but centralised secrets**
Moving credentials out of individual pipelines reduces the number of places a token can be leaked or stolen. However, ROVER then becomes a high-value target: a single compromise exposes credentials and a detailed map of your software inventory. The net security posture depends entirely on how well the ROVER instance itself is secured.

**Vulnerability aggregation enables correlation — and creates a honeypot**
A unified vulnerability database makes cross-product analysis and compliance reporting straightforward. It also means a single data breach exposes the full vulnerability state of your organisation's software. Treat the ROVER database with the same access controls you would apply to a production secrets store.

**Self-hosting means control — and responsibility**
You own the data, the uptime SLA, and the upgrade schedule. For some organisations this is a feature; for others it is an unwanted burden that commercial SaaS eliminates.

---

## Quick Comparison

| Dimension | ROVER | Typical Commercial Alternative |
|---|---|---|
| Cost | Free | Per-seat or per-scan licensing |
| Data residency | Fully on-premises | Vendor cloud (configurable) |
| Source auditability | Full source available | Black box |
| Maintenance | Community / self | Vendor SLA |
| Helm-native tracking | ✅ | Rarely |
| RBAC | ✅ | ✅ |
| Runtime / cloud posture | ❌ | Often ✅ |
| HA / multi-instance | ❌ (roadmap) | Usually ✅ |
| Support contract | ❌ | ✅ |
