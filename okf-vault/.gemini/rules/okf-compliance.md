# OKF Compliance Rules

<RULE[okf_v0_2_schema]>
1. All created markdown notes MUST contain valid YAML frontmatter delimiters `---` at the beginning of the file.
2. Frontmatter MUST include:
   - `id`: 12-digit timestamp string (`YYYYMMDDHHMM`)
   - `type`: One of `Concept`, `Resource`, `Index`, `Log`, `Meta`
   - `title`: String title
   - `created`: ISO-8601 UTC timestamp
   - `updated`: ISO-8601 UTC timestamp
   - `tags`: List of string tags
   - `status`: One of `draft`, `stable`, `deprecated`
   - `stale_after`: YYYY-MM-DD string date
3. Do NOT create unorganized markdown files at the root of the vault. Place notes in their designated numeric directory (`10_inbox`, `20_concepts`, `30_resources`, `40_indices`, `50_archive`).
</RULE[okf_v0_2_schema]>
