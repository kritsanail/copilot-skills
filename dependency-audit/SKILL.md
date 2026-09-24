---
name: dependency-audit
description: Detect a project's package ecosystem and perform a read-only dependency audit with SBOM inventory, transitive dependencies, potentially unused package evidence, known vulnerabilities, and cached Markdown/PDF reports. Use for dependency governance, security review, compliance evidence, or software inventory assessment.
argument-hint: "[project path] [--refresh-cve]"
---

# Dependency audit

Run the bundled analyzer instead of reconstructing dependency data in the model context:

```bash
node "${SKILL_DIR}/scripts/audit.mjs" "${PROJECT_PATH:-.}"
```

If `SKILL_DIR` is unavailable, resolve `scripts/audit.mjs` relative to this `SKILL.md`. The script must detect the ecosystem before selecting an adapter; do not infer it from the user's wording. Pass `--refresh-cve` only when the user requests fresh vulnerability data or the cached result is stale.

After the command completes, read only `<project>/dependency-audit-reports/summary.json` unless the user asks for detailed evidence. Report the generated Markdown, PDF, SBOM, raw JSON paths, scan timestamp, coverage, and scanner failures. A missing scanner or failed data source is a coverage limitation, not proof that no issue exists.

The current adapter audits Node.js projects detected from their manifests or lockfiles. If another ecosystem is detected, report it as detected-but-unsupported and stop without running Node commands. This skill is audit-only: do not install, update, uninstall, auto-fix, edit source files, or modify manifests and lockfiles. Treat potentially unused packages as findings requiring human verification, not removal instructions.
