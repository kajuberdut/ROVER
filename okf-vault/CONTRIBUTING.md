# Contributing to OKF Vault (ROVER Knowledge Base)

Thank you for contributing to this Open Knowledge Format (OKF) v0.2 knowledge base for **ROVER (Release Oriented Vulnerability Evaluation & Reporting)**! To maintain architectural consistency, open-source shareability, and automated validation, please follow these guidelines.

---

## 1. Quickstart: Adding a New Note

1. **Select Note Type & Location**:
   - Atomic security, vulnerability, or scanner concepts -> `20_concepts/<kebab-case-name>.md`
   - External tool documentation (Trivy, Semgrep, OpenBao, Authelia) -> `30_resources/<kebab-case-name>.md`
   - Maps of Content (MOCs) or topic hubs -> `40_indices/<kebab-case-name>-moc.md`
   - Daily logs or meeting captures -> `10_inbox/` (initially) or `log/<YYYY-MM-DD>.md`

2. **Copy the Corresponding Template**:
   Templates are located in `00_meta/templates/`:
   - [concept_template.md](file:///home/giblesnot/code/ROVER/okf-vault/00_meta/templates/concept_template.md)
   - [resource_template.md](file:///home/giblesnot/code/ROVER/okf-vault/00_meta/templates/resource_template.md)
   - [index_template.md](file:///home/giblesnot/code/ROVER/okf-vault/00_meta/templates/index_template.md)
   - [log_template.md](file:///home/giblesnot/code/ROVER/okf-vault/00_meta/templates/log_template.md)

3. **Fill Required Metadata**:
   Ensure all required frontmatter fields (`id`, `type`, `title`, `created`, `updated`, `tags`) are populated.

4. **Validate Schema**:
   Run the schema validator before opening a PR or finalizing edits:
   ```bash
   python3 scripts/validate_schema.py
   ```

---

## 2. Note Lifecycle & Status Workflow

Every note progresses through three status phases:

```
[10_inbox] --(Drafting)--> 20_concepts/ (status: draft)
                               |
                        (Review & Verify)
                               v
                     20_concepts/ (status: stable)
                               |
                         (Superceded)
                               v
                     50_archive/ (status: deprecated)
```

- **`draft`**: Note is incomplete or undergoing refinement.
- **`stable`**: Note is verified, complete, and reliable (default status).
- **`deprecated`**: Note is replaced by a newer concept or historical record. Move to `50_archive/`.

---

## 3. Staleness (`stale_after`) Guidelines

When creating security policies or scanner configuration definitions subject to periodic re-approval (e.g. CVE severity thresholds or scanner DB refresh rules):
- Set `stale_after` to an absolute date `YYYY-MM-DD` (e.g. `2026-12-31`).
- Avoid relative phrases like "in 6 months" in frontmatter.

---

## 4. Linking & Cross-Referencing

- Use **Wikilinks** (`[[Note Title]]` or `[[Note Title|Alias]]`) or standard Markdown links (`[Title](./path/to/note.md)`).
- When referencing parent indices, link back to the relevant Map of Content in `40_indices/`.

---

## 5. Antigravity CLI (AGY) Integration

If using the **Antigravity CLI (AGY)**, the AI agent automatically enforces OKF rules defined in `.gemini/AGENTS.md` and `.gemini/rules/okf-compliance.md`.
