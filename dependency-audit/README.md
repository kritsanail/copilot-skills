# Dependency Audit Skill

An Agent Skill for GitHub Copilot in VS Code that automatically detects a project's package ecosystem and performs a read-only dependency audit. It does not modify source code, manifests, lockfiles, or installed packages.

The current release supports auditing Node.js projects. Its ecosystem-neutral structure is ready for future Python, Java, .NET, Go, Rust, and other adapters. When it detects an unsupported ecosystem, it reports the detection evidence and stops without running Node.js commands.

Key capabilities:

- Generate a dependency inventory and CycloneDX SBOM
- List direct and transitive dependencies
- Identify potentially unused dependencies with static evidence
- Scan for known vulnerabilities using the package manager's audit command
- Distinguish production and development dependencies when data is available
- Record timestamps, coverage, and scanner failures as audit evidence
- Generate Markdown, PDF, and JSON reports
- Cache scan results to reduce repeated work and model context usage

## Requirements

- Node.js 18 or later for the detector and Node.js adapter
- A `package.json` file for Node.js projects; a supported lockfile improves package-manager and resolved-version detection
- npm, pnpm, or Yarn, according to the project's lockfile
- Python 3 and `reportlab` for PDF generation

Install the PDF dependency:

```bash
python3 -m pip install reportlab
```

If `reportlab` is unavailable, the audit, Markdown report, JSON results, and SBOM still work. PDF generation is reported as skipped.

## Install for VS Code

### Repository-level installation

Copy this directory to:

```text
<repository>/.github/skills/dependency-audit/
```

The resulting structure must be:

```text
.github/skills/dependency-audit/
├── SKILL.md
├── README.md
├── requirements.txt
└── scripts/
    ├── audit.mjs
    └── render_pdf.py
```

### Personal installation

Copy this directory to:

```text
~/.copilot/skills/dependency-audit/
```

Restart VS Code, or open the Command Palette and run `Chat: Open Customizations` to verify that the skill was discovered. You can also enter `/skills` in the Chat input to open the Skills menu.

## Use with Copilot Chat

Open the target repository in VS Code, select Agent mode, and use a prompt such as:

```text
Use dependency-audit to detect this project's ecosystem and perform a read-only dependency audit. Generate SBOM, unused dependency evidence, CVE findings, coverage status, Markdown, and PDF reports. Do not modify the project.
```

## Run without a model

Run the script directly when you do not need Copilot to interpret the results:

```bash
node .github/skills/dependency-audit/scripts/audit.mjs .
```

Force a fresh vulnerability scan instead of using the CVE cache:

```bash
node .github/skills/dependency-audit/scripts/audit.mjs . --refresh-cve
```

Specify a custom output directory:

```bash
node .github/skills/dependency-audit/scripts/audit.mjs . --output reports/dependency-audit
```

## Outputs

```text
dependency-audit-reports/
├── dependency-audit.md
├── dependency-audit.pdf
├── dependency-inventory.json
├── potential-unused.json
├── vulnerability-results.json
├── sbom.cdx.json
└── summary.json
```

For a concise response, Copilot should read only `summary.json`. The remaining files provide detailed evidence when requested. This minimizes context and credit usage.

## Cache

The cache is stored in `<project>/.dependency-audit-cache/`. Dependency inventory, unused-dependency evidence, and SBOM data are reused while the manifest and lockfile fingerprint remains unchanged. Vulnerability data has a default time-to-live of 12 hours.

Set the vulnerability cache lifetime in hours:

```bash
DEPENDENCY_AUDIT_CVE_TTL_HOURS=24 node .github/skills/dependency-audit/scripts/audit.mjs .
```

Add these paths to `.gitignore` if audit artifacts should not be committed:

```gitignore
.dependency-audit-cache/
dependency-audit-reports/
```

## Ecosystem detection

The script detects ecosystems from files in the project root, including:

- Node.js: `package.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`
- Python: `pyproject.toml`, `requirements.txt`, `poetry.lock`, `uv.lock`
- Java: `pom.xml`, `build.gradle`, `build.gradle.kts`
- .NET: `*.csproj`, `packages.lock.json`
- Go: `go.mod`
- Rust: `Cargo.toml`
- PHP: `composer.json`
- Ruby: `Gemfile`

Non-Node.js ecosystems are currently detection-only and return `detected-but-unsupported`. This prevents the skill from running an incorrect package-manager workflow.

## Limitations

- Static unused-dependency detection can produce false positives for dynamic imports, dependency injection, framework plugins, generated code, and configuration that references packages indirectly.
- Vulnerability results depend on registry or network availability and the active package manager. A failed scan does not prove that no vulnerabilities exist.
- `npm audit` does not cover every dependency type equally, so reports always include coverage and error information.
- A potentially unused dependency is an audit finding, not an instruction to remove the package.
- The skill does not perform remediation, upgrades, uninstallation, or project-file changes.

See [VS Code Agent Skills](https://code.visualstudio.com/docs/agent-customization/agent-skills) and [GitHub Copilot Agent Skills](https://docs.github.com/en/copilot/how-tos/copilot-on-github/customize-copilot/customize-cloud-agent/add-skills) for supported skill locations and discovery behavior.
