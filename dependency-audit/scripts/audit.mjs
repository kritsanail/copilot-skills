#!/usr/bin/env node

import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { basename, dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const args = process.argv.slice(2);
const projectArg = args.find((arg) => !arg.startsWith("--")) || ".";
const option = (name, fallback) => {
  const index = args.indexOf(name);
  return index >= 0 && args[index + 1] && !args[index + 1].startsWith("--") ? args[index + 1] : fallback;
};
const projectRoot = resolve(projectArg);
const outputDir = resolve(projectRoot, option("--output", "dependency-audit-reports"));
const cacheDir = resolve(projectRoot, ".dependency-audit-cache");
const refreshCve = args.includes("--refresh-cve");
const ttlHours = Number(process.env.DEPENDENCY_AUDIT_CVE_TTL_HOURS || 12);
const scriptDir = dirname(fileURLToPath(import.meta.url));

const detection = detectProject(projectRoot);
if (!detection.selected) {
  console.error(`No supported project manifest or lockfile detected: ${projectRoot}`);
  process.exit(2);
}
mkdirSync(outputDir, { recursive: true });
if (detection.selected !== "node") {
  const unsupported = {
    status: "detected-but-unsupported",
    generatedAt: new Date().toISOString(),
    project: { root: projectRoot, ecosystem: detection.selected, detectedEcosystems: detection.detected, evidence: detection.evidence },
    message: `The ${detection.selected} ecosystem was detected, but this version only includes the Node.js audit adapter.`,
  };
  writeJson(join(outputDir, "summary.json"), unsupported);
  console.log(JSON.stringify(unsupported, null, 2));
  process.exit(3);
}
if (!existsSync(join(projectRoot, "package.json"))) {
  const incomplete = {
    status: "incomplete-project",
    generatedAt: new Date().toISOString(),
    project: { root: projectRoot, ecosystem: "node", detectedEcosystems: detection.detected, evidence: detection.evidence },
    message: "Node.js markers were detected, but package.json is required for the Node.js audit adapter.",
  };
  writeJson(join(outputDir, "summary.json"), incomplete);
  console.log(JSON.stringify(incomplete, null, 2));
  process.exit(4);
}
mkdirSync(cacheDir, { recursive: true });

const manifest = JSON.parse(readFileSync(join(projectRoot, "package.json"), "utf8"));
const lockCandidates = ["package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"];
const lockfile = lockCandidates.find((name) => existsSync(join(projectRoot, name)));
const manager = lockfile?.startsWith("pnpm") ? "pnpm" : lockfile === "yarn.lock" ? "yarn" : "npm";
const fingerprint = hashFiles(["package.json", lockfile].filter(Boolean).map((name) => join(projectRoot, name)));
const cacheMetaPath = join(cacheDir, "meta.json");
const oldMeta = readJson(cacheMetaPath, {});
const dependencyCacheHit = oldMeta.fingerprint === fingerprint && existsSync(join(cacheDir, "inventory.json"));

let inventory;
if (dependencyCacheHit) {
  inventory = readJson(join(cacheDir, "inventory.json"), null);
} else {
  inventory = collectInventory(manager, manifest);
  writeJson(join(cacheDir, "inventory.json"), inventory);
}

let unused;
if (dependencyCacheHit && existsSync(join(cacheDir, "unused.json"))) {
  unused = readJson(join(cacheDir, "unused.json"), null);
} else {
  unused = detectPotentialUnused(manifest);
  writeJson(join(cacheDir, "unused.json"), unused);
}

const cveCachePath = join(cacheDir, "vulnerabilities.json");
const cveFresh = !refreshCve && oldMeta.fingerprint === fingerprint && existsSync(cveCachePath)
  && Date.now() - Number(oldMeta.cveScannedAt || 0) < ttlHours * 3600_000;
const vulnerabilities = cveFresh ? readJson(cveCachePath, null) : scanVulnerabilities(manager);
if (!cveFresh) writeJson(cveCachePath, vulnerabilities);

const sbom = dependencyCacheHit && existsSync(join(cacheDir, "sbom.cdx.json"))
  ? readJson(join(cacheDir, "sbom.cdx.json"), null)
  : createSbom(inventory, manifest);
writeJson(join(cacheDir, "sbom.cdx.json"), sbom);

const summary = buildSummary(inventory, unused, vulnerabilities, {
  manager,
  lockfile: lockfile || null,
  detection,
  fingerprint,
  dependencyCache: dependencyCacheHit ? "hit" : "miss",
  vulnerabilityCache: cveFresh ? "hit" : "miss",
});

writeJson(join(outputDir, "dependency-inventory.json"), inventory);
writeJson(join(outputDir, "potential-unused.json"), unused);
writeJson(join(outputDir, "vulnerability-results.json"), vulnerabilities);
writeJson(join(outputDir, "sbom.cdx.json"), sbom);
writeJson(join(outputDir, "summary.json"), summary);
writeFileSync(join(outputDir, "dependency-audit.md"), renderMarkdown(summary, unused, vulnerabilities), "utf8");

const python = findCommand([process.env.PYTHON, "python3", "python"]);
let pdfStatus = { status: "skipped", reason: "Python was not found" };
if (python) {
  const result = spawnSync(python, [join(scriptDir, "render_pdf.py"), join(outputDir, "summary.json"), join(outputDir, "dependency-audit.pdf")], {
    cwd: projectRoot,
    encoding: "utf8",
  });
  pdfStatus = result.status === 0
    ? { status: "generated", path: join(outputDir, "dependency-audit.pdf") }
    : { status: "skipped", reason: (result.stderr || result.stdout || "PDF renderer failed").trim() };
}
summary.reports.pdf = pdfStatus;
writeJson(join(outputDir, "summary.json"), summary);

writeJson(cacheMetaPath, {
  fingerprint,
  analyzedAt: Date.now(),
  cveScannedAt: cveFresh ? oldMeta.cveScannedAt : Date.now(),
});

console.log(JSON.stringify({
  status: "ok",
  summary: join(outputDir, "summary.json"),
  markdown: join(outputDir, "dependency-audit.md"),
  pdf: pdfStatus,
  cache: summary.cache,
}, null, 2));

function run(command, commandArgs) {
  const result = spawnSync(command, commandArgs, { cwd: projectRoot, encoding: "utf8", maxBuffer: 100 * 1024 * 1024 });
  return { status: result.status, stdout: result.stdout || "", stderr: result.stderr || "", error: result.error?.message };
}

function collectInventory(packageManager, packageJson) {
  const commandArgs = packageManager === "npm"
    ? ["ls", "--all", "--json", "--long"]
    : packageManager === "pnpm" ? ["list", "--json", "--depth", "Infinity"] : ["list", "--json"];
  const result = run(packageManager, commandArgs);
  let tree = null;
  try { tree = JSON.parse(result.stdout); } catch {}
  const direct = [
    ...Object.entries(packageJson.dependencies || {}).map(([name, requested]) => ({ name, requested, type: "production" })),
    ...Object.entries(packageJson.devDependencies || {}).map(([name, requested]) => ({ name, requested, type: "development" })),
    ...Object.entries(packageJson.optionalDependencies || {}).map(([name, requested]) => ({ name, requested, type: "optional" })),
  ];
  const flattened = [];
  const seen = new Set();
  walkDependencyTree(tree, [], flattened, seen);
  return {
    packageManager,
    command: `${packageManager} ${commandArgs.join(" ")}`,
    commandStatus: result.status,
    warning: result.status !== 0 ? compact(result.stderr || result.error || "dependency command returned non-zero") : null,
    direct,
    packages: flattened,
  };
}

function walkDependencyTree(node, path, output, seen) {
  if (!node || typeof node !== "object") return;
  if (Array.isArray(node)) return node.forEach((item) => walkDependencyTree(item, path, output, seen));
  const deps = node.dependencies || {};
  for (const [name, value] of Object.entries(deps)) {
    const version = value?.version || value?.resolution || "unknown";
    const key = `${name}@${version}`;
    if (!seen.has(key)) {
      seen.add(key);
      output.push({ name, version, path: [...path, name].join(" > "), dev: Boolean(value?.dev), optional: Boolean(value?.optional) });
    }
    walkDependencyTree(value, [...path, name], output, seen);
  }
}

function detectPotentialUnused(packageJson) {
  const dependencyEntries = [
    ...Object.keys(packageJson.dependencies || {}).map((name) => ({ name, type: "production" })),
    ...Object.keys(packageJson.devDependencies || {}).map((name) => ({ name, type: "development" })),
    ...Object.keys(packageJson.optionalDependencies || {}).map((name) => ({ name, type: "optional" })),
  ];
  const searchable = [];
  const ignored = new Set(["node_modules", ".git", ".next", "dist", "build", "coverage", "dependency-audit-reports", ".dependency-audit-cache"]);
  walkFiles(projectRoot, searchable, ignored);
  const contents = searchable.map((path) => safeRead(path)).join("\n");
  const scriptText = JSON.stringify(packageJson.scripts || {});
  const results = dependencyEntries.map((dep) => {
    const escaped = escapeRegExp(dep.name);
    const codePattern = new RegExp(`(?:from\\s*[\\\"']|require\\s*\\(\\s*[\\\"']|import\\s*\\(\\s*[\\\"']|import\\s*[\\\"'])${escaped}(?:[/\\\"'])`);
    const mentioned = codePattern.test(contents) || new RegExp(`(^|[^a-zA-Z0-9@/_-])${escaped}([^a-zA-Z0-9@/_-]|$)`).test(scriptText);
    return { ...dep, status: mentioned ? "evidence-found" : "possibly-unused", confidence: mentioned ? 100 : 70 };
  });
  return {
    method: "static import/require/dynamic-import and package-script scan",
    filesScanned: searchable.length,
    limitations: ["dynamic package names", "dependency injection", "framework plugins", "generated code", "external scripts"],
    packages: results,
  };
}

function walkFiles(directory, output, ignored) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (ignored.has(entry.name)) continue;
    const full = join(directory, entry.name);
    if (entry.isDirectory()) walkFiles(full, output, ignored);
    else if (entry.isFile() && statSync(full).size < 2_000_000 && [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".json", ".yaml", ".yml"].includes(extname(entry.name))) output.push(full);
  }
}

function scanVulnerabilities(packageManager) {
  const args = packageManager === "yarn" ? ["npm", "audit", "--json"] : ["audit", "--json"];
  const result = run(packageManager, args);
  let raw = null;
  try { raw = JSON.parse(result.stdout); } catch {}
  const findings = [];
  const vulnerabilities = raw?.vulnerabilities || {};
  for (const [name, item] of Object.entries(vulnerabilities)) {
    findings.push({
      id: item.via?.find((v) => typeof v === "object")?.source || item.via?.find((v) => typeof v === "object")?.url || "advisory",
      package: name,
      severity: item.severity || "unknown",
      direct: Boolean(item.isDirect),
      range: item.range || null,
      fixAvailable: item.fixAvailable ?? null,
      via: item.via || [],
      nodes: item.nodes || [],
    });
  }
  return {
    source: `${packageManager} ${args.join(" ")}`,
    status: result.status === 0 ? "complete" : raw ? "findings-or-nonzero" : "failed",
    warning: !raw ? compact(result.stderr || result.error || "audit output was not valid JSON") : null,
    metadata: raw?.metadata || null,
    findings,
  };
}

function createSbom(inventoryData, packageJson) {
  const components = inventoryData.packages.map((pkg) => ({
    type: "library",
    name: pkg.name,
    version: pkg.version,
    purl: pkg.version !== "unknown" ? `pkg:npm/${encodeURIComponent(pkg.name)}@${encodeURIComponent(pkg.version)}` : undefined,
    properties: [{ name: "dependency:path", value: pkg.path }],
  }));
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${cryptoRandomUuid()}`,
    version: 1,
    metadata: { timestamp: new Date().toISOString(), component: { type: "application", name: packageJson.name || basename(projectRoot), version: packageJson.version || "0.0.0" } },
    components,
  };
}

function buildSummary(inventoryData, unusedData, vulnerabilityData, meta) {
  const severity = { critical: 0, high: 0, moderate: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  for (const item of vulnerabilityData.findings || []) severity[item.severity] = (severity[item.severity] || 0) + 1;
  return {
    generatedAt: new Date().toISOString(),
    project: { root: projectRoot, name: manifest.name || basename(projectRoot), version: manifest.version || null, ecosystem: "node", detectedEcosystems: meta.detection.detected, detectionEvidence: meta.detection.evidence, packageManager: meta.manager, lockfile: meta.lockfile },
    dependencies: { direct: inventoryData.direct.length, uniqueResolved: inventoryData.packages.length, possiblyUnused: unusedData.packages.filter((item) => item.status === "possibly-unused").length },
    vulnerabilities: { total: vulnerabilityData.findings?.length || 0, severity, scanStatus: vulnerabilityData.status, warning: vulnerabilityData.warning },
    cache: { dependencyScan: meta.dependencyCache, vulnerabilityScan: meta.vulnerabilityCache, fingerprint: meta.fingerprint },
    coverage: { dependencyCommandStatus: inventoryData.commandStatus, unusedMethod: unusedData.method, vulnerabilitySource: vulnerabilityData.source },
    reports: {
      markdown: join(outputDir, "dependency-audit.md"),
      pdf: { status: "pending" },
      sbom: join(outputDir, "sbom.cdx.json"),
      inventory: join(outputDir, "dependency-inventory.json"),
      unused: join(outputDir, "potential-unused.json"),
      vulnerabilities: join(outputDir, "vulnerability-results.json"),
    },
  };
}

function renderMarkdown(data, unusedData, vulnerabilityData) {
  const unusedRows = unusedData.packages.filter((item) => item.status === "possibly-unused")
    .map((item) => `| ${escapeCell(item.name)} | ${item.type} | ${item.confidence}% | Manual verification required |`).join("\n") || "| - | - | - | None detected |";
  const vulnerabilityRows = (vulnerabilityData.findings || []).map((item) =>
    `| ${escapeCell(String(item.id))} | ${escapeCell(item.package)} | ${item.severity} | ${item.direct ? "direct" : "transitive"} | ${escapeCell(formatFix(item.fixAvailable))} |`
  ).join("\n") || "| - | - | - | - | No findings returned |";
  return `# Dependency Audit\n\nGenerated: ${data.generatedAt}\n\n> Read-only audit. No project files were modified. Static unused detection and registry audits can have coverage gaps. Findings require verification in the project context.\n\n## Project detection\n\n- Selected ecosystem: ${data.project.ecosystem}\n- Detected ecosystems: ${data.project.detectedEcosystems.join(", ")}\n- Package manager: ${data.project.packageManager}\n- Detection evidence: ${data.project.detectionEvidence.join(", ")}\n\n## Audit summary\n\n| Metric | Value |\n|---|---:|\n| Direct dependencies | ${data.dependencies.direct} |\n| Unique resolved packages | ${data.dependencies.uniqueResolved} |\n| Potentially unused findings | ${data.dependencies.possiblyUnused} |\n| Known vulnerability findings | ${data.vulnerabilities.total} |\n| Critical | ${data.vulnerabilities.severity.critical || 0} |\n| High | ${data.vulnerabilities.severity.high || 0} |\n| Moderate/Medium | ${(data.vulnerabilities.severity.moderate || 0) + (data.vulnerabilities.severity.medium || 0)} |\n\n## Potentially unused findings\n\n| Package | Type | Confidence | Audit disposition |\n|---|---|---:|---|\n${unusedRows}\n\n## Vulnerability findings\n\nScan source: \`${data.coverage.vulnerabilitySource}\`  \nStatus: \`${data.vulnerabilities.scanStatus}\`\n\n| Advisory | Package | Severity | Relationship | Fix information |\n|---|---|---|---|---|\n${vulnerabilityRows}\n\n## Audit evidence\n\n- CycloneDX SBOM: \`${relative(projectRoot, data.reports.sbom)}\`\n- Dependency inventory: \`${relative(projectRoot, data.reports.inventory)}\`\n- Unused evidence: \`${relative(projectRoot, data.reports.unused)}\`\n- Raw vulnerability result: \`${relative(projectRoot, data.reports.vulnerabilities)}\`\n\n## Coverage and cache\n\n- Dependency command status: ${data.coverage.dependencyCommandStatus}\n- Vulnerability status: ${data.vulnerabilities.scanStatus}\n- Vulnerability warning: ${data.vulnerabilities.warning || "none"}\n- Dependency scan cache: ${data.cache.dependencyScan}\n- Vulnerability scan cache: ${data.cache.vulnerabilityScan}\n- Fingerprint: \`${data.cache.fingerprint}\`\n`;
}

function detectProject(root) {
  const rules = [
    ["node", ["package.json", "package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock"]],
    ["python", ["pyproject.toml", "requirements.txt", "poetry.lock", "uv.lock", "Pipfile"]],
    ["java", ["pom.xml", "build.gradle", "build.gradle.kts", "gradle.lockfile"]],
    ["dotnet", ["packages.lock.json"]],
    ["go", ["go.mod"]],
    ["rust", ["Cargo.toml", "Cargo.lock"]],
    ["php", ["composer.json", "composer.lock"]],
    ["ruby", ["Gemfile", "Gemfile.lock"]],
  ];
  const rootFiles = readdirSync(root, { withFileTypes: true }).filter((entry) => entry.isFile()).map((entry) => entry.name);
  const matches = [];
  for (const [ecosystem, markers] of rules) {
    const evidence = markers.filter((marker) => rootFiles.includes(marker));
    if (ecosystem === "dotnet") evidence.push(...rootFiles.filter((name) => name.endsWith(".csproj")));
    if (evidence.length) matches.push({ ecosystem, evidence: [...new Set(evidence)] });
  }
  const node = matches.find((item) => item.ecosystem === "node");
  const selected = node?.ecosystem || matches[0]?.ecosystem || null;
  return { selected, detected: matches.map((item) => item.ecosystem), evidence: matches.flatMap((item) => item.evidence) };
}

function hashFiles(paths) {
  const hash = createHash("sha256");
  for (const path of paths) hash.update(path).update(readFileSync(path));
  return hash.digest("hex");
}
function readJson(path, fallback) { try { return JSON.parse(readFileSync(path, "utf8")); } catch { return fallback; } }
function writeJson(path, value) { writeFileSync(path, JSON.stringify(value, null, 2) + "\n", "utf8"); }
function safeRead(path) { try { return readFileSync(path, "utf8"); } catch { return ""; } }
function compact(value) { return String(value).replace(/\s+/g, " ").trim().slice(0, 500); }
function escapeRegExp(value) { return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); }
function escapeCell(value) { return String(value ?? "").replace(/\|/g, "\\|").replace(/\s+/g, " "); }
function formatFix(value) { return value === true ? "available" : value === false || value == null ? "none reported" : JSON.stringify(value); }
function findCommand(candidates) {
  for (const candidate of candidates.filter(Boolean)) {
    const found = spawnSync(candidate, ["--version"], { encoding: "utf8" });
    if (!found.error) return candidate;
  }
  return null;
}
function cryptoRandomUuid() {
  const bytes = createHash("sha256").update(`${projectRoot}:${fingerprint}`).digest("hex").slice(0, 32).split("");
  bytes[12] = "4";
  bytes[16] = ["8", "9", "a", "b"][parseInt(bytes[16], 16) % 4];
  return `${bytes.slice(0, 8).join("")}-${bytes.slice(8, 12).join("")}-${bytes.slice(12, 16).join("")}-${bytes.slice(16, 20).join("")}-${bytes.slice(20).join("")}`;
}
