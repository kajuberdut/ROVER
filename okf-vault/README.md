# Open Knowledge Format (OKF) Vault Framework for ROVER

[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![OKF Version](https://img.shields.io/badge/OKF-v0.2-green.svg)](00_meta/okf-spec-v0.2.md)

A production-ready, skeletal knowledge base framework adhering strictly to the **Open Knowledge Format (OKF) v0.2** standard, tailored for **R.O.V.E.R (Release Oriented Vulnerability Evaluation & Reporting)**. Designed for seamless human authoring, AI agent interaction (via Antigravity CLI / AGY), and tool-agnostic open-source sharing.

---

## 🌟 Key Features

- **Strict OKF v0.2 Compliance**: Native support for provenance (`sources`), trust (`generated`, `verified`), and deterministic freshness (`stale_after`, `status`).
- **Tool-Agnostic Design**: Compatible with Logseq, VS Code, Obsidian, static site generators, and custom parsers without vendor lock-in or proprietary plugin dependencies.
- **Deterministic Directory Structure**: Clean, numeric folder hierarchy (`00_meta`, `10_inbox`, `20_concepts`, `30_resources`, `40_indices`, `50_archive`).
- **Antigravity CLI (AGY) Integration**: Pre-configured with `.gemini/AGENTS.md` and `.gemini/rules/okf-compliance.md` for AI agent interaction.
- **Automated Validation**: Includes a Python schema validator (`scripts/validate_schema.py`) to verify note frontmatter.

---

## 📂 Directory Layout

```
okf-vault/
├── 00_meta/                  # System definitions, templates, JSON schemas, & OKF v0.2 spec
│   ├── okf-spec-v0.2.md      # Official OKF v0.2 Specification document
│   ├── schemas/              # JSON Schema validator definitions
│   └── templates/            # Markdown templates (concept, resource, index, log)
├── 10_inbox/                 # Capture zone for un-triaged scan outputs
├── 20_concepts/              # Atomized security & scanner concepts
├── 30_resources/              # External references, tool docs, & assets
├── 40_indices/               # Maps of Content (MOCs) & navigation hubs
├── 50_archive/               # Deprecated and historical notes
├── .gemini/                  # Antigravity CLI rules & instructions
├── scripts/                  # Schema validation script (validate_schema.py)
├── CONTRIBUTING.md           # Contribution guidelines & workflow
├── LICENSE                   # Apache 2.0 License
├── README.md                 # Project overview and quickstart
└── SYSTEM_ARCHITECTURE.md    # Vault architecture & blueprint
```

---

## 🚀 Quickstart & Usage

### 1. Cloned Vault Setup
To use this framework as a starting blueprint for a new knowledge base:
```bash
git clone <your-repo-url> okf-vault
cd okf-vault
```

### 2. Creating a Note
Copy one of the standardized templates from `00_meta/templates/`:
```bash
cp 00_meta/templates/concept_template.md 20_concepts/my-new-concept.md
```

### 3. Validating Frontmatter
Verify that all notes comply with the OKF v0.2 specification:
```bash
python3 scripts/validate_schema.py
```

---

## 📖 Key Documentation Links

- [Official OKF v0.2 Specification](file:///home/giblesnot/code/ROVER/okf-vault/00_meta/okf-spec-v0.2.md)
- [Vault System Architecture & Blueprint](file:///home/giblesnot/code/ROVER/okf-vault/SYSTEM_ARCHITECTURE.md)
- [Contributing Guidelines](file:///home/giblesnot/code/ROVER/okf-vault/CONTRIBUTING.md)
- [License (Apache 2.0)](file:///home/giblesnot/code/ROVER/okf-vault/LICENSE)

---

## 🤝 License

Distributed under the **Apache 2.0 License**. See [LICENSE](LICENSE) for details.
