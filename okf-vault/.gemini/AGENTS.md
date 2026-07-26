# Antigravity CLI Instructions for OKF Vault

When modifying, creating, or inspecting notes in `okf-vault`, you MUST adhere strictly to the Open Knowledge Format (OKF) v0.2 specification.

## Core Rules
1. **Frontmatter Integrity**: Every new markdown note MUST include standard OKF v0.2 YAML frontmatter (`id`, `type`, `title`, `created`, `updated`, `tags`, `status`, `stale_after`, `aliases`).
2. **File Naming & Locations**:
   - Concepts: `20_concepts/<kebab-case-title>.md`
   - Resources: `30_resources/<kebab-case-title>.md`
   - Indices: `40_indices/<kebab-case-title>-moc.md`
   - Daily Logs: `log/<YYYY-MM-DD>.md`
3. **Status Taxonomy**: `status: draft` -> `status: stable` -> `status: deprecated`. Note is assumed `stable` if status is omitted.
4. **Stale After Policy**: Always specify an absolute YYYY-MM-DD date for `stale_after` when creating policy or metric concepts.
5. **Linking**: Use Wikilinks `[[Note Title]]` or relative markdown links.

## Validation Command
Run the Python schema validator before committing changes:
```bash
python3 scripts/validate_schema.py
```
