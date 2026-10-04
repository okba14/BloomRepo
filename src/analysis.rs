//! Bounded, read-only analysis of a caller-authorized local directory.
//! No repository programs, hooks, package managers, or Git commands are run.
//! Secure traversal supports Windows and Linux x86_64/aarch64 (5.6+ with procfs).

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_FILES: usize = 10_000;
const MAX_ENTRIES: usize = 30_000;
const MAX_DEPTH: usize = 24;
const MAX_FILE_BYTES: u64 = 1024 * 1024;
const MAX_TOTAL_BYTES: u64 = 50 * 1024 * 1024;
const MAX_DEPENDENCIES: usize = 5_000;
const MAX_FINDINGS: usize = 1_000;
const LOCAL_TIMEOUT: Duration = Duration::from_secs(20);
const MAX_OSV_QUERIES: usize = 100;
const OSV_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_OSV_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub severity: String,
    pub rule: String,
    pub path: String,
    pub line: Option<usize>,
    pub evidence: String,
    pub remediation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct Dependency {
    pub ecosystem: String,
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub generated_at: String,
    pub root: String,
    pub files_scanned: usize,
    pub skipped: usize,
    pub limits: Vec<String>,
    pub findings: Vec<Finding>,
    pub dependencies: Vec<Dependency>,
    #[serde(default)]
    pub coverage_gaps: Vec<String>,
    #[serde(default)]
    pub osv_requested: bool,
    #[serde(default)]
    pub osv_queries: usize,
}

impl AnalysisReport {
    pub fn markdown(&self) -> String {
        let mut out = format!(
            "# Local Directory Analysis\n\nRoot: {}\n\nGenerated: {}\n\nFiles scanned: {}; skipped entries: {}; dependencies: {}.\n\nThis is a bounded static review, not proof that the project is safe. No repository code was executed. Secret values and source snippets are not retained.\n",
            markdown_text(&self.root), markdown_text(&self.generated_at),
            self.files_scanned, self.skipped, self.dependencies.len()
        );
        if self.osv_requested {
            out.push_str(&format!("\nOSV was enabled: {} requests attempted. Only validated dependency names, versions, and ecosystems are sent to https://api.osv.dev/v1/query, not paths or source contents.\n", self.osv_queries));
        } else {
            out.push_str("\nOffline: no vulnerability service was contacted. Known-vulnerability coverage is unavailable.\n");
        }
        out.push_str("\n## Limits\n");
        for limit in &self.limits {
            out.push_str(&format!("- {}\n", markdown_text(limit)));
        }
        out.push_str("\n## Coverage Gaps\n");
        if self.coverage_gaps.is_empty() {
            out.push_str("No additional gaps recorded. Static rules and inventory remain incomplete by design.\n");
        }
        for gap in &self.coverage_gaps {
            out.push_str(&format!("- {}\n", markdown_text(gap)));
        }
        out.push_str("\n## Findings\n");
        if self.findings.is_empty() {
            out.push_str("No matching findings within the scanned scope. This is not a clean bill of health.\n");
        }
        for f in &self.findings {
            let line = f.line.map(|n| format!(":{n}")).unwrap_or_default();
            out.push_str(&format!(
                "\n### {}: {}\n\nLocation: {}{}\n\n{}\n\nRemediation: {}\n",
                markdown_text(&f.severity),
                markdown_text(&f.rule),
                markdown_text(&f.path),
                line,
                markdown_text(&f.evidence),
                markdown_text(&f.remediation)
            ));
        }
        out.push_str(
            "\n## Dependency Inventory\n\n| Ecosystem | Name | Version |\n| --- | --- | --- |\n",
        );
        for d in &self.dependencies {
            out.push_str(&format!(
                "| {} | {} | {} |\n",
                markdown_text(&d.ecosystem),
                markdown_text(&d.name),
                markdown_text(&d.version)
            ));
        }
        out
    }

    /// CycloneDX 1.5 inventory, not an attestation of completeness or vulnerability absence.
    pub fn sbom_json(&self) -> Value {
        let components: Vec<Value> = self
            .dependencies
            .iter()
            .enumerate()
            .map(|(i, d)| {
                let mut component = json!({
                    "type": "library", "bom-ref": format!("dependency-{}", i + 1),
                    "name": d.name, "version": d.version,
                    "properties": [{"name": "bloomrepo:ecosystem", "value": d.ecosystem}]
                });
                if let Some(purl) = dependency_purl(d) {
                    component["purl"] = Value::String(purl);
                }
                component
            })
            .collect();
        json!({
            "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
            "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
            "metadata": {
                "timestamp": self.generated_at,
                "tools": [{"vendor": "BloomRepo", "name": "Local directory analyzer"}],
                "properties": [
                    {"name": "bloomrepo:scope", "value": "Bounded local static inventory; not a complete SBOM or security attestation"},
                    {"name": "bloomrepo:coverage-gaps", "value": self.coverage_gaps.join("; ")}
                ]
            },
            "components": components
        })
    }
}

/// Consent belongs to the caller. `query_osv` explicitly opts into dependency-only disclosure.
pub async fn analyze_directory(path: &Path, query_osv: bool) -> Result<AnalysisReport, String> {
    let path = path.to_path_buf();
    let cancelled = Arc::new(AtomicBool::new(false));
    // Dropping this future also cancels cooperative traversal on the blocking worker.
    struct Cancel(Arc<AtomicBool>);
    impl Drop for Cancel {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Relaxed);
        }
    }
    let guard = Cancel(cancelled.clone());
    let worker = tokio::task::spawn_blocking(move || scan_local(&path, cancelled));
    let mut report = match tokio::time::timeout(LOCAL_TIMEOUT + Duration::from_secs(2), worker)
        .await
    {
        Ok(Ok(result)) => result?,
        Ok(Err(_)) => return Err("Local analyzer worker failed.".into()),
        Err(_) => return Err(
            "Local analysis timed out; blocking filesystem calls cannot be forcibly interrupted."
                .into(),
        ),
    };
    drop(guard);
    report.osv_requested = query_osv;
    if query_osv {
        query_vulnerabilities(&mut report).await;
    } else {
        add_unique(
            &mut report.coverage_gaps,
            "Known vulnerabilities were not queried (offline mode).".into(),
        );
    }
    Ok(report)
}

struct Rules {
    secrets: Vec<(&'static str, Regex)>,
    target: Regex,
    uses: Regex,
    run: Regex,
    interpolation: Regex,
    checkout_ref: Regex,
    pinned_requirement: Regex,
}

impl Rules {
    fn new() -> Self {
        Self {
            secrets: vec![
                ("secret.github-token", Regex::new(r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})").unwrap()),
                ("secret.aws-access-key", Regex::new(r"(?:AKIA|ASIA)[A-Z0-9]{16}").unwrap()),
                ("secret.private-key", Regex::new(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----").unwrap()),
            ],
            target: Regex::new(r#"(?:^|[\s\[,{:'"])pull_request_target(?:\s*[:\]},'"]|\s*$)"#).unwrap(),
            uses: Regex::new(r"^\s*(?:-\s*)?uses\s*:\s*(.+?)\s*$").unwrap(),
            run: Regex::new(r"^\s*(?:-\s*)?run\s*:\s*(.*)$").unwrap(),
            interpolation: Regex::new(r"\$\{\{\s*(?:github\.event\.(?:pull_request\.(?:title|body|head\.(?:ref|label))|issue\.(?:title|body)|comment\.body|review\.body|discussion\.(?:title|body))|github\.head_ref)\s*(?:\}\}|[|&!=])").unwrap(),
            checkout_ref: Regex::new(r"\$\{\{\s*(?:github\.event\.pull_request\.head\.(?:sha|ref|repo\.full_name)|github\.head_ref)\s*\}\}").unwrap(),
            pinned_requirement: Regex::new(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[A-Za-z0-9_,.-]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)$").unwrap(),
        }
    }

    fn scrub(&self, text: &str) -> String {
        let mut result = text
            .chars()
            .map(|c| if c.is_control() { '?' } else { c })
            .collect::<String>();
        for (_, regex) in &self.secrets {
            result = regex.replace_all(&result, "[REDACTED]").into_owned();
        }
        result.chars().take(1024).collect()
    }

    fn contains_secret(&self, text: &str) -> bool {
        self.secrets.iter().any(|(_, re)| re.is_match(text))
    }
}

struct Scanner {
    report: AnalysisReport,
    rules: Rules,
    dependencies: BTreeSet<Dependency>,
    visited: usize,
    bytes: u64,
    started: Instant,
    cancelled: Arc<AtomicBool>,
}

fn scan_local(path: &Path, cancelled: Arc<AtomicBool>) -> Result<AnalysisReport, String> {
    let (root, canonical) = secure_fs::open_root(path)?;
    let rules = Rules::new();
    let mut scanner = Scanner {
        report: AnalysisReport {
            generated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
            root: rules.scrub(&canonical.to_string_lossy()), files_scanned: 0, skipped: 0,
            limits: vec![
                format!("At most {MAX_FILES} files, {MAX_ENTRIES} directory entries, depth {MAX_DEPTH}, 1 MiB per file, 50 MiB total, and 20 seconds of cooperative local work."),
                format!("At most {MAX_DEPENDENCIES} unique dependencies, {MAX_FINDINGS} findings, and {MAX_OSV_QUERIES} sequential OSV requests within 30 seconds when explicitly enabled."),
                "Symlinks, junctions/reparse points, hard-linked regular files, .git, generated/vendor directories, non-regular files, and hidden files/directories are skipped; .github and .env / .env.* are exceptions.".into(),
                "Timeouts are cooperative for synchronous filesystem calls; the OS may stall a call. Files may change during analysis; this is not a filesystem snapshot.".into(),
            ],
            findings: Vec::new(), dependencies: Vec::new(), coverage_gaps: vec![
                "Secret detection is limited to recognizable GitHub tokens, AWS access-key IDs, and private-key headers; an AWS key ID alone is not a usable credential.".into(),
                "GitHub Actions checks are conservative line/indentation heuristics, not a full YAML/expression interpreter; aliases, reusable workflows, and dynamic values may be missed.".into(),
                "Dependency inventory is local and partial; license metadata is not evaluated. SBOM declarations are unverified and no dependency resolution is performed.".into(),
            ], osv_requested: false, osv_queries: 0,
        },
        rules, dependencies: BTreeSet::new(), visited: 0, bytes: 0,
        started: Instant::now(), cancelled,
    };
    scanner.walk(&root, Path::new(""), 0);
    if scanner.dependencies.is_empty() {
        scanner.gap("No supported exact dependency versions were inventoried.");
    }
    scanner.report.dependencies = scanner.dependencies.into_iter().collect();
    Ok(scanner.report)
}

impl Scanner {
    fn gap(&mut self, text: &str) {
        add_unique(&mut self.report.coverage_gaps, text.to_owned());
    }

    fn stopped(&mut self) -> bool {
        if self.cancelled.load(Ordering::Relaxed) || self.started.elapsed() >= LOCAL_TIMEOUT {
            self.gap("Local time limit reached; traversal is incomplete.");
            true
        } else if self.visited >= MAX_ENTRIES
            || self.report.files_scanned >= MAX_FILES
            || self.bytes >= MAX_TOTAL_BYTES
        {
            self.gap("Entry, file-count, or total-byte limit reached; traversal is incomplete.");
            true
        } else {
            false
        }
    }

    fn walk(&mut self, directory: &File, relative: &Path, depth: usize) {
        if self.stopped() {
            return;
        }
        // Enumerate one bounded chunk at a time, never collect an entire hostile directory.
        let mut entries = match secure_fs::Entries::new(directory) {
            Ok(entries) => entries,
            Err(_) => {
                self.report.skipped += 1;
                self.gap("A directory could not be enumerated safely.");
                return;
            }
        };
        while !self.stopped() {
            let name = match entries.next_entry() {
                Some(Ok(name)) => name,
                Some(Err(_)) => {
                    self.report.skipped += 1;
                    self.gap("Directory enumeration failed; traversal is incomplete.");
                    break;
                }
                None => break,
            };
            self.visited += 1;
            let name_path = Path::new(&name);
            if name_path.components().count() != 1
                || !matches!(name_path.components().next(), Some(Component::Normal(_)))
            {
                self.report.skipped += 1;
                self.gap("Invalid directory entry rejected.");
                continue;
            }
            let display = name.to_string_lossy();
            if skip_name(&display) {
                self.report.skipped += 1;
                self.gap("Excluded hidden, VCS, vendor, or generated entries were not inspected.");
                continue;
            }
            let file = match secure_fs::open_child(directory, name_path) {
                Ok(file) => file,
                Err(_) => {
                    self.report.skipped += 1;
                    self.gap("A link, reparse point, inaccessible entry, or unsafe filesystem was skipped.");
                    continue;
                }
            };
            let metadata = match file.metadata() {
                Ok(metadata) => metadata,
                Err(_) => {
                    self.report.skipped += 1;
                    self.gap("An entry's metadata could not be read.");
                    continue;
                }
            };
            let child_path = relative.join(name_path);
            if metadata.is_dir() {
                if depth >= MAX_DEPTH {
                    self.report.skipped += 1;
                    self.gap("Maximum directory depth reached; deeper entries were skipped.");
                } else {
                    self.walk(&file, &child_path, depth + 1);
                }
            } else if metadata.is_file() {
                self.scan_file(file, &child_path, metadata.len());
            } else {
                self.report.skipped += 1;
                self.gap("Non-regular files were skipped.");
            }
        }
    }

    fn scan_file(&mut self, file: File, relative: &Path, length: u64) {
        if length > MAX_FILE_BYTES || length > MAX_TOTAL_BYTES.saturating_sub(self.bytes) {
            self.report.skipped += 1;
            self.gap("Files exceeding the per-file or remaining total-byte budget were skipped.");
            return;
        }
        let budget = MAX_FILE_BYTES.min(MAX_TOTAL_BYTES.saturating_sub(self.bytes));
        let mut data = Vec::new();
        let read = file.take(budget + 1).read_to_end(&mut data);
        self.bytes = self.bytes.saturating_add(data.len() as u64);
        if read.is_err() || data.len() as u64 > budget {
            self.report.skipped += 1;
            self.gap("A file could not be fully read within the byte budget.");
            return;
        }
        self.report.files_scanned += 1;
        if self.stopped() && self.started.elapsed() >= LOCAL_TIMEOUT {
            return;
        }
        let text = match std::str::from_utf8(&data) {
            Ok(text) if !data.contains(&0) => text,
            _ => {
                self.report.skipped += 1;
                self.gap("Binary or non-UTF-8 content was not analyzed.");
                return;
            }
        };
        let path = self
            .rules
            .scrub(&relative.to_string_lossy().replace('\\', "/"));
        // Never retain the match or any surrounding source text in a finding.
        for (line, source) in text.lines().enumerate() {
            if line % 256 == 0
                && (self.cancelled.load(Ordering::Relaxed)
                    || self.started.elapsed() >= LOCAL_TIMEOUT)
            {
                self.gap(
                    "Local time limit reached during content analysis; coverage is incomplete.",
                );
                return;
            }
            for index in 0..self.rules.secrets.len() {
                let (rule, regex) = &self.rules.secrets[index];
                if regex.is_match(source) {
                    let rule = *rule;
                    self.finding("high", rule, &path, Some(line + 1),
                        "A recognizable credential identifier or private-key header matched. Value and source context are redacted; validity is not verified.",
                        "Check whether this is a real credential. If exposed, revoke/rotate it and remove it from tracked files and history; use an appropriate secret store.");
                }
            }
        }
        if path.starts_with(".github/workflows/")
            && (path.ends_with(".yml") || path.ends_with(".yaml"))
        {
            self.scan_workflow(text, &path);
        }
        let name = relative.file_name().and_then(|n| n.to_str()).unwrap_or("");
        match name {
            "Cargo.lock" => self.cargo_lock(text),
            "package-lock.json" | "npm-shrinkwrap.json" => self.npm_lock(text),
            "uv.lock" => self.uv_lock(text),
            "pyproject.toml" => self.pyproject(text),
            "Cargo.toml" => self.gap("Cargo.toml declarations are not resolved; Cargo.lock is needed for exact installed versions."),
            "package.json" => self.gap("package.json declarations are not resolved; npm lockfiles are needed for exact versions."),
            "yarn.lock" | "pnpm-lock.yaml" | "poetry.lock" | "Pipfile.lock" | "go.mod" | "go.sum" | "Gemfile.lock" | "composer.lock" | "pom.xml" | "packages.lock.json" => self.gap("An unsupported dependency manifest/lockfile was encountered; its dependency coverage is unavailable."),
            _ if name.starts_with("requirements") && name.ends_with(".txt") => self.requirements(text),
            _ => {},
        }
        if name.ends_with(".json") {
            // Look for explicit format markers; do not interpret arbitrary JSON as an SBOM.
            if text.contains("\"bomFormat\"") || text.contains("\"spdxVersion\"") {
                self.import_sbom(text);
            } else if name.to_ascii_lowercase().contains("sbom") {
                self.gap("An SBOM-like file lacked a supported CycloneDX/SPDX JSON format marker.");
            }
        } else if name.to_ascii_lowercase().contains("sbom") || name.ends_with(".spdx") {
            self.gap("Only CycloneDX and SPDX JSON SBOM imports are supported; other encodings were not parsed.");
        }
    }

    fn finding(
        &mut self,
        severity: &str,
        rule: &str,
        path: &str,
        line: Option<usize>,
        evidence: &str,
        remediation: &str,
    ) {
        if self.report.findings.len() >= MAX_FINDINGS {
            self.gap("Finding limit reached; additional matches were omitted.");
            return;
        }
        self.report.findings.push(Finding {
            severity: severity.into(),
            rule: rule.into(),
            path: path.into(),
            line,
            evidence: evidence.into(),
            remediation: remediation.into(),
        });
    }

    fn dependency(&mut self, ecosystem: &str, name: &str, version: &str) {
        if self.rules.contains_secret(name) || self.rules.contains_secret(version) {
            self.gap("A credential-shaped dependency identifier was omitted and will not be sent to OSV.");
            return;
        }
        let name = if ecosystem == "PyPI" {
            normalize_pypi(name)
        } else {
            name.to_owned()
        };
        if !valid_dependency(ecosystem, &name, version)
            || self.rules.contains_secret(&name)
            || self.rules.contains_secret(version)
        {
            self.gap("A dependency lacked a supported ecosystem, safe package identifier, or exact version; it was omitted (and will not be sent to OSV).");
            return;
        }
        let dependency = Dependency {
            ecosystem: ecosystem.into(),
            name,
            version: version.into(),
        };
        if self.dependencies.len() >= MAX_DEPENDENCIES && !self.dependencies.contains(&dependency) {
            self.gap("Unique dependency limit reached; inventory is incomplete.");
            return;
        }
        self.dependencies.insert(dependency);
    }

    fn cargo_lock(&mut self, text: &str) {
        let doc = match text.parse::<toml::Value>() {
            Ok(doc) => doc,
            Err(_) => {
                self.gap("Cargo.lock could not be parsed.");
                return;
            }
        };
        let Some(packages) = doc.get("package").and_then(toml::Value::as_array) else {
            self.gap("Cargo.lock has no supported package list.");
            return;
        };
        for package in packages {
            let source = package
                .get("source")
                .and_then(toml::Value::as_str)
                .unwrap_or("");
            if source != "registry+https://github.com/rust-lang/crates.io-index"
                && source != "sparse+https://index.crates.io/"
            {
                self.gap("Cargo local, Git, or alternative-registry packages were not treated as crates.io dependencies.");
                continue;
            }
            match (
                package.get("name").and_then(toml::Value::as_str),
                package.get("version").and_then(toml::Value::as_str),
            ) {
                (Some(name), Some(version)) => self.dependency("crates.io", name, version),
                _ => self.gap("A Cargo.lock package lacked a name/version."),
            }
        }
    }

    fn npm_lock(&mut self, text: &str) {
        let doc: Value = match serde_json::from_str(text) {
            Ok(doc) => doc,
            Err(_) => {
                self.gap("An npm lockfile could not be parsed.");
                return;
            }
        };
        if let Some(packages) = doc.get("packages").and_then(Value::as_object) {
            for (location, package) in packages {
                if location.is_empty() {
                    continue;
                }
                if package.get("link").and_then(Value::as_bool) == Some(true) {
                    self.gap("npm workspace/link packages were not resolved.");
                    continue;
                }
                let Some((_, inferred)) = location.rsplit_once("node_modules/") else {
                    self.gap("npm local/workspace package entries were not resolved.");
                    continue;
                };
                let name = package
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(inferred);
                self.npm_package(name, package);
            }
        } else if let Some(dependencies) = doc.get("dependencies").and_then(Value::as_object) {
            let mut stack = vec![(dependencies, 0)];
            let mut visited = 0;
            while let Some((packages, depth)) = stack.pop() {
                for (name, package) in packages {
                    visited += 1;
                    if visited > MAX_ENTRIES {
                        self.gap("npm dependency-entry limit reached.");
                        return;
                    }
                    self.npm_package(name, package);
                    if let Some(children) = package.get("dependencies").and_then(Value::as_object) {
                        if depth < MAX_DEPTH {
                            stack.push((children, depth + 1));
                        } else {
                            self.gap("npm dependency nesting limit reached.");
                        }
                    }
                }
            }
        } else {
            self.gap("An npm lockfile had no supported dependency list.");
        }
    }

    fn npm_package(&mut self, name: &str, package: &Value) {
        // Custom registries and tarballs can shadow public npm package identities.
        if let Some(resolved) = package.get("resolved").and_then(Value::as_str) {
            if !resolved.starts_with("https://registry.npmjs.org/") {
                self.gap("npm Git, file, tarball, or alternative-registry packages were omitted to avoid misidentification.");
                return;
            }
        } else {
            self.gap("Some npm lock entries omit registry provenance; public npm identity is assumed for valid package/version pairs.");
        }
        if let Some(version) = package.get("version").and_then(Value::as_str) {
            self.dependency("npm", name, version);
        } else {
            self.gap("An npm dependency lacked an exact version.");
        }
    }

    fn requirements(&mut self, text: &str) {
        for line in text.lines() {
            let line = line.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            if line.contains(';') {
                self.gap("Python environment markers were not evaluated; pinned requirements are inventoried regardless of environment.");
            }
            let base = line
                .split(';')
                .next()
                .unwrap_or("")
                .split(" --hash=")
                .next()
                .unwrap_or("")
                .trim();
            if let Some(captures) = self.rules.pinned_requirement.captures(base) {
                let name = captures[1].to_owned();
                let version = captures[2].to_owned();
                self.dependency("PyPI", &name, &version);
            } else {
                self.gap("Unpinned/unsupported Python requirements, includes, indexes, URLs, or options were not resolved or followed.");
            }
        }
    }

    fn pyproject(&mut self, text: &str) {
        let doc = match text.parse::<toml::Value>() {
            Ok(doc) => doc,
            Err(_) => {
                self.gap("pyproject.toml could not be parsed.");
                return;
            }
        };
        if let Some(project) = doc.get("project") {
            if let Some(deps) = project.get("dependencies").and_then(toml::Value::as_array) {
                for dep in deps {
                    if let Some(dep) = dep.as_str() {
                        self.requirements(dep);
                    } else {
                        self.gap("A pyproject dependency was not a supported string.");
                    }
                }
            }
            if let Some(groups) = project
                .get("optional-dependencies")
                .and_then(toml::Value::as_table)
            {
                self.gap("Optional Python dependencies are inventoried without selecting extras.");
                for deps in groups.values().filter_map(toml::Value::as_array) {
                    for dep in deps.iter().filter_map(toml::Value::as_str) {
                        self.requirements(dep);
                    }
                }
            }
        }
        self.gap("pyproject dynamic/tool/build dependencies are not resolved; exact declarations are not proof of installed versions.");
    }

    fn uv_lock(&mut self, text: &str) {
        let doc = match text.parse::<toml::Value>() {
            Ok(doc) => doc,
            Err(_) => {
                self.gap("uv.lock could not be parsed.");
                return;
            }
        };
        let Some(packages) = doc.get("package").and_then(toml::Value::as_array) else {
            self.gap("uv.lock lacked a supported package list.");
            return;
        };
        for package in packages {
            let registry = package
                .get("source")
                .and_then(|s| s.get("registry"))
                .and_then(toml::Value::as_str);
            if !matches!(
                registry,
                Some("https://pypi.org/simple" | "https://pypi.org/simple/")
            ) {
                self.gap("uv local/Git/alternative-index dependencies were not treated as PyPI packages.");
                continue;
            }
            match (
                package.get("name").and_then(toml::Value::as_str),
                package.get("version").and_then(toml::Value::as_str),
            ) {
                (Some(name), Some(version)) => self.dependency("PyPI", name, version),
                _ => self.gap("A uv.lock dependency lacked a name/version."),
            }
        }
        self.gap("uv environment markers and dependency groups were not evaluated.");
    }

    fn import_sbom(&mut self, text: &str) {
        let doc: Value = match serde_json::from_str(text) {
            Ok(doc) => doc,
            Err(_) => {
                self.gap("An SBOM JSON document could not be parsed.");
                return;
            }
        };
        if doc.get("bomFormat").and_then(Value::as_str) == Some("CycloneDX") {
            let Some(components) = doc.get("components").and_then(Value::as_array) else {
                self.gap("CycloneDX SBOM lacked a component list.");
                return;
            };
            let mut stack = vec![(components, 0)];
            let mut visited = 0;
            while let Some((components, depth)) = stack.pop() {
                for component in components {
                    visited += 1;
                    if visited > MAX_ENTRIES {
                        self.gap("SBOM component-entry limit reached.");
                        return;
                    }
                    self.sbom_purl(
                        component.get("purl").and_then(Value::as_str),
                        component.get("version").and_then(Value::as_str),
                    );
                    if let Some(children) = component.get("components").and_then(Value::as_array) {
                        if depth < MAX_DEPTH {
                            stack.push((children, depth + 1));
                        } else {
                            self.gap("SBOM component nesting limit reached.");
                        }
                    }
                }
            }
        } else if doc
            .get("spdxVersion")
            .and_then(Value::as_str)
            .is_some_and(|s| s.starts_with("SPDX-2."))
        {
            let Some(packages) = doc.get("packages").and_then(Value::as_array) else {
                self.gap("SPDX SBOM lacked a package list.");
                return;
            };
            for package in packages.iter().take(MAX_ENTRIES) {
                let purl = package
                    .get("externalRefs")
                    .and_then(Value::as_array)
                    .and_then(|refs| {
                        refs.iter().find(|r| {
                            r.get("referenceType").and_then(Value::as_str) == Some("purl")
                        })
                    })
                    .and_then(|r| r.get("referenceLocator"))
                    .and_then(Value::as_str);
                self.sbom_purl(purl, package.get("versionInfo").and_then(Value::as_str));
            }
            if packages.len() > MAX_ENTRIES {
                self.gap("SPDX package-entry limit reached.");
            }
        } else {
            self.gap("An SBOM used an unsupported format/version.");
        }
    }

    fn sbom_purl(&mut self, purl: Option<&str>, declared_version: Option<&str>) {
        if let Some(dep) = purl.and_then(parse_purl) {
            if declared_version.is_some_and(|v| v != dep.version) {
                self.gap(
                    "An SBOM package had conflicting declared and purl versions; it was omitted.",
                );
                return;
            }
            self.dependency(&dep.ecosystem, &dep.name, &dep.version);
        } else {
            self.gap("An SBOM component lacked an exact supported cargo/npm/pypi purl; its identity was not guessed.");
        }
    }

    fn scan_workflow(&mut self, text: &str, path: &str) {
        let mut scalar_indent = None;
        let lines: Vec<String> = text
            .lines()
            .map(|line| {
                let indent = line.len() - line.trim_start().len();
                // GitHub expands expressions in shell comments too; scalar contents are not YAML comments.
                if line.trim().is_empty() || scalar_indent.is_some_and(|base| indent > base) {
                    return line.to_owned();
                }
                let code = yaml_code(line);
                if !code.trim().is_empty() {
                    scalar_indent = self
                        .rules
                        .run
                        .captures(&code)
                        .filter(|c| matches!(c[1].trim_start().chars().next(), Some('|' | '>')))
                        .map(|_| {
                            indent
                                + if code.trim_start().starts_with('-') {
                                    2
                                } else {
                                    0
                                }
                        });
                }
                code
            })
            .collect();
        let mut event_block = false;
        let mut target = false;
        for code in &lines {
            if code.trim().is_empty() {
                continue;
            }
            let indent = code.len() - code.trim_start().len();
            if indent == 0 {
                event_block = code
                    .split_once(':')
                    .is_some_and(|(key, _)| key.trim().trim_matches(['\'', '"']) == "on");
            }
            if event_block && self.rules.target.is_match(code) {
                target = true;
            }
        }
        let mut run_indent = None;
        let mut checkout_indent = None;
        let mut checkout_untrusted = None;
        for (index, code) in lines.iter().enumerate() {
            if code.trim().is_empty() {
                continue;
            }
            let indent = code.len() - code.trim_start().len();
            if run_indent.is_some_and(|base| indent > base) {
                if self.rules.interpolation.is_match(code) {
                    self.finding("high", "ci.untrusted-run-interpolation", path, Some(index + 1),
                        "A run command directly interpolates a recognized attacker-influenced GitHub event field. Shell injection is possible depending on quoting, trigger, and data flow; exploitability is not established.",
                        "Pass event text through an environment variable and quote it as data; do not place GitHub expressions containing untrusted text directly in shell source.");
                }
                continue;
            }
            run_indent = None;
            if code.trim_start().starts_with('-') {
                if let Some(line) = checkout_untrusted.take() {
                    self.checkout_finding(target, path, line);
                }
                checkout_indent = None;
            }
            if checkout_indent.is_some_and(|base| indent < base) {
                if let Some(line) = checkout_untrusted.take() {
                    self.checkout_finding(target, path, line);
                }
                checkout_indent = None;
            }
            if code
                .trim()
                .trim_matches(|c| c == '\'' || c == '"')
                .starts_with("permissions:")
            {
                let value = code
                    .split_once(':')
                    .map(|(_, v)| v.trim().trim_matches(|c| c == '\'' || c == '"'))
                    .unwrap_or("");
                if value == "write-all" {
                    self.finding("medium", "ci.broad-write-permissions", path, Some(index + 1),
                        "A permissions declaration requests write-all. Effective permissions depend on workflow/job overrides and repository policy; this is not an exploit claim.",
                        "Use read-only permissions by default and grant only the specific writes required by each job.");
                }
            }
            if let Some(captures) = self.rules.uses.captures(code) {
                let action = captures[1]
                    .trim()
                    .trim_matches(|c| c == '\'' || c == '"')
                    .to_owned();
                let key_indent = indent
                    + if code.trim_start().starts_with('-') {
                        2
                    } else {
                        0
                    };
                if action.starts_with("actions/checkout@") {
                    checkout_indent = Some(key_indent);
                }
                if !action.starts_with("./") {
                    let pinned = if action.starts_with("docker://") {
                        action
                            .rsplit_once("@sha256:")
                            .is_some_and(|(_, hash)| is_hex(hash, 64))
                    } else {
                        action
                            .rsplit_once('@')
                            .is_some_and(|(_, hash)| is_hex(hash, 40))
                    };
                    if !pinned {
                        self.finding("low", "ci.mutable-action-reference", path, Some(index + 1),
                            "An external action/container reference is not pinned to a full commit SHA/SHA-256 digest. Tags, branches, and dynamic references can change; publisher trust and update policy still matter.",
                            "Review the publisher and pin the reviewed commit/digest; keep a deliberate process for security updates.");
                    }
                }
            }
            if checkout_indent.is_some()
                && self.rules.checkout_ref.is_match(code)
                && matches!(
                    code.trim_start().split(':').next(),
                    Some("ref" | "repository")
                )
            {
                checkout_untrusted = Some(index + 1);
            }
            let inline = self.rules.run.captures(code).map(|c| c[1].to_owned());
            if let Some(value) = &inline {
                if matches!(value.trim_start().chars().next(), Some('|' | '>')) {
                    run_indent = Some(
                        indent
                            + if code.trim_start().starts_with('-') {
                                2
                            } else {
                                0
                            },
                    );
                }
            }
            if (inline.is_some() || run_indent.is_some()) && self.rules.interpolation.is_match(code)
            {
                self.finding("high", "ci.untrusted-run-interpolation", path, Some(index + 1),
                    "A run command directly interpolates a recognized attacker-influenced GitHub event field. Shell injection is possible depending on quoting, trigger, and data flow; exploitability is not established.",
                    "Pass event text through an environment variable and quote it as data; do not place GitHub expressions containing untrusted text directly in shell source.");
            }
        }
        if let Some(line) = checkout_untrusted {
            self.checkout_finding(target, path, line);
        }
    }

    fn checkout_finding(&mut self, target: bool, path: &str, line: usize) {
        if target {
            self.finding("high", "ci.pull-request-target-untrusted-checkout", path, Some(line),
                "A workflow mentioning pull_request_target explicitly checks out a pull-request head reference/repository. Running that checkout could expose privileged credentials; this analyzer does not establish that the checkout is executed or that code is run.",
                "Do not execute untrusted pull-request code in privileged pull_request_target jobs. Use isolated pull_request jobs with read-only permissions and no secrets.");
        }
    }
}

fn skip_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if lower == ".github" || lower == ".env" || lower.starts_with(".env.") {
        return false;
    }
    lower.starts_with('.')
        || matches!(
            lower.as_str(),
            "node_modules"
                | "target"
                | "vendor"
                | "dist"
                | "build"
                | "__pycache__"
                | "venv"
                | "coverage"
        )
}

fn add_unique(list: &mut Vec<String>, text: String) {
    if !list.contains(&text) {
        list.push(text);
    }
}

fn markdown_text(text: &str) -> String {
    let mut result = String::new();
    for c in text.chars() {
        match c {
            '&' => result.push_str("&amp;"),
            '<' => result.push_str("&lt;"),
            '>' => result.push_str("&gt;"),
            '\\' | '`' | '*' | '_' | '[' | ']' | '|' | '#' => {
                result.push('\\');
                result.push(c);
            }
            c if c.is_control() => result.push(' '),
            c => result.push(c),
        }
    }
    result
}

fn yaml_code(line: &str) -> String {
    let mut quote = None;
    let mut escape = false;
    for (index, c) in line.char_indices() {
        if escape {
            escape = false;
            continue;
        }
        if quote == Some('"') && c == '\\' {
            escape = true;
            continue;
        }
        if c == '\'' || c == '"' {
            if quote == Some(c) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(c);
            }
        } else if c == '#'
            && quote.is_none()
            && (index == 0 || line[..index].ends_with(char::is_whitespace))
        {
            return line[..index].to_owned();
        }
    }
    line.to_owned()
}

fn is_hex(text: &str, length: usize) -> bool {
    text.len() == length && text.bytes().all(|b| b.is_ascii_hexdigit())
}

fn normalize_pypi(name: &str) -> String {
    let mut normalized = String::new();
    for c in name.chars() {
        if matches!(c, '-' | '_' | '.') {
            if !normalized.ends_with('-') {
                normalized.push('-');
            }
        } else {
            normalized.push(c.to_ascii_lowercase());
        }
    }
    normalized
}

fn valid_dependency(ecosystem: &str, name: &str, version: &str) -> bool {
    if name.is_empty() || name.len() > 214 || version.is_empty() || version.len() > 128 {
        return false;
    }
    if !version.bytes().next().is_some_and(|b| b.is_ascii_digit())
        || !version
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".-_+!".contains(&b))
    {
        return false;
    }
    let part = |s: &str| {
        !s.is_empty()
            && s.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
    };
    match ecosystem {
        "npm" => {
            if let Some(scoped) = name.strip_prefix('@') {
                scoped
                    .split_once('/')
                    .is_some_and(|(scope, name)| part(scope) && part(name))
            } else {
                part(name)
            }
        }
        "crates.io" | "PyPI" => part(name),
        _ => false,
    }
}

fn percent_encode(text: &str) -> String {
    let mut out = String::new();
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || b".-_~".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn percent_decode(text: &str) -> Option<String> {
    let mut out = Vec::new();
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let digits = std::str::from_utf8(bytes.get(index + 1..index + 3)?).ok()?;
            out.push(u8::from_str_radix(digits, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn dependency_purl(dep: &Dependency) -> Option<String> {
    if !valid_dependency(&dep.ecosystem, &dep.name, &dep.version) {
        return None;
    }
    let kind = match dep.ecosystem.as_str() {
        "crates.io" => "cargo",
        "npm" => "npm",
        "PyPI" => "pypi",
        _ => return None,
    };
    let name = dep
        .name
        .split('/')
        .map(percent_encode)
        .collect::<Vec<_>>()
        .join("/");
    Some(format!(
        "pkg:{kind}/{name}@{}",
        percent_encode(&dep.version)
    ))
}

fn parse_purl(purl: &str) -> Option<Dependency> {
    if purl.len() > 1024 || purl.contains(['?', '#']) {
        return None;
    }
    let (kind, coordinate) = purl.strip_prefix("pkg:")?.split_once('/')?;
    let (name, version) = coordinate.rsplit_once('@')?;
    let ecosystem = match kind {
        "cargo" => "crates.io",
        "npm" => "npm",
        "pypi" => "PyPI",
        _ => return None,
    };
    let name = percent_decode(name)?;
    let version = percent_decode(version)?;
    valid_dependency(ecosystem, &name, &version).then(|| Dependency {
        ecosystem: ecosystem.into(),
        name,
        version,
    })
}

async fn query_vulnerabilities(report: &mut AnalysisReport) {
    let client = match reqwest::Client::builder()
        .https_only(true)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(6))
        .gzip(false)
        .brotli(false)
        .deflate(false)
        .user_agent("BloomRepo-Local-Analyzer/1")
        .build()
    {
        Ok(client) => client,
        Err(_) => {
            add_unique(
                &mut report.coverage_gaps,
                "OSV client could not be initialized; vulnerability coverage is unavailable."
                    .into(),
            );
            return;
        }
    };
    let rules = Rules::new();
    let deadline = tokio::time::Instant::now() + OSV_TIMEOUT;
    if report.dependencies.len() > MAX_OSV_QUERIES {
        add_unique(
            &mut report.coverage_gaps,
            "OSV query-count limit excludes some dependencies.".into(),
        );
    }
    for index in 0..report.dependencies.len().min(MAX_OSV_QUERIES) {
        if tokio::time::Instant::now() >= deadline {
            add_unique(
                &mut report.coverage_gaps,
                "OSV total-time limit reached; not all selected dependencies were queried.".into(),
            );
            break;
        }
        let dep = &report.dependencies[index];
        if !valid_dependency(&dep.ecosystem, &dep.name, &dep.version)
            || rules.contains_secret(&dep.name)
            || rules.contains_secret(&dep.version)
        {
            add_unique(
                &mut report.coverage_gaps,
                "Unsafe dependency identifiers were excluded from OSV requests.".into(),
            );
            continue;
        }
        let body = json!({"package": {"ecosystem": dep.ecosystem, "name": dep.name}, "version": dep.version});
        report.osv_queries += 1;
        let response = tokio::time::timeout_at(deadline, async {
            let mut response = client
                .post("https://api.osv.dev/v1/query")
                .json(&body)
                .send()
                .await
                .map_err(|_| ())?;
            if !response.status().is_success()
                || response
                    .content_length()
                    .is_some_and(|len| len > MAX_OSV_BYTES as u64)
            {
                return Err(());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| ())? {
                if bytes.len().saturating_add(chunk.len()) > MAX_OSV_BYTES {
                    return Err(());
                }
                bytes.extend_from_slice(&chunk);
            }
            serde_json::from_slice::<Value>(&bytes).map_err(|_| ())
        })
        .await;
        let doc = match response {
            Ok(Ok(doc)) if doc.is_object() => doc,
            _ => {
                add_unique(&mut report.coverage_gaps, "An OSV request failed, timed out, was redirected, or exceeded the response budget; vulnerability coverage is incomplete.".into());
                continue;
            }
        };
        let dep = dep.clone();
        apply_osv_response(report, &dep, &doc, &rules);
    }
}

fn apply_osv_response(report: &mut AnalysisReport, dep: &Dependency, doc: &Value, rules: &Rules) {
    if doc.get("error").is_some() {
        add_unique(
            &mut report.coverage_gaps,
            "OSV returned an error; vulnerability coverage is incomplete.".into(),
        );
        return;
    }
    let vulns = match doc.get("vulns") {
        None if doc.is_object() => return,
        Some(Value::Array(vulns)) => vulns,
        _ => {
            add_unique(
                &mut report.coverage_gaps,
                "An OSV response had an unsupported vulnerability list.".into(),
            );
            return;
        }
    };
    for vuln in vulns {
        if vuln.get("withdrawn").is_some_and(|v| !v.is_null()) {
            continue;
        }
        let Some(id) = vuln.get("id").and_then(Value::as_str).filter(|id| {
            !id.is_empty()
                && id.len() <= 100
                && id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
                && !rules.contains_secret(id)
        }) else {
            add_unique(
                &mut report.coverage_gaps,
                "An OSV advisory lacked a safe identifier and was omitted.".into(),
            );
            continue;
        };
        if report.findings.len() >= MAX_FINDINGS {
            add_unique(
                &mut report.coverage_gaps,
                "Finding limit reached; additional OSV advisories were omitted.".into(),
            );
            break;
        }
        report.findings.push(Finding {
                severity: "unknown".into(), rule: "dependency.osv-advisory".into(), path: "dependency inventory".into(), line: None,
                evidence: format!("OSV matched {id} to {} {} {}. Advisory severity is not inferred; declared versions and upstream matching have not been independently verified.", dep.ecosystem, dep.name, dep.version),
                remediation: "Review the identified advisory at osv.dev, verify applicability, and select a supported patched version. No dependencies were installed or modified.".into(),
            });
    }
}

// Handle-relative opens avoid check-then-open races and never traverse repository links.
// Other platforms fail closed rather than silently offering weaker pathname traversal.
#[cfg(windows)]
mod secure_fs {
    use super::*;
    use std::ffi::{c_void, OsString};
    use std::os::windows::ffi::{OsStrExt, OsStringExt};
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::ptr::{null, null_mut};

    #[repr(C)]
    struct UnicodeString {
        length: u16,
        maximum_length: u16,
        buffer: *mut u16,
    }
    #[repr(C)]
    struct ObjectAttributes {
        length: u32,
        root: *mut c_void,
        name: *mut UnicodeString,
        attributes: u32,
        security: *mut c_void,
        qos: *mut c_void,
    }
    #[repr(C)]
    struct IoStatus {
        status: usize,
        information: usize,
    }
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtCreateFile(
            handle: *mut *mut c_void,
            access: u32,
            attributes: *mut ObjectAttributes,
            status: *mut IoStatus,
            allocation: *const i64,
            file_attributes: u32,
            share: u32,
            disposition: u32,
            options: u32,
            ea: *const c_void,
            ea_length: u32,
        ) -> i32;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandleEx(
            handle: *mut c_void,
            class: u32,
            info: *mut c_void,
            size: u32,
        ) -> i32;
        fn GetFinalPathNameByHandleW(
            handle: *mut c_void,
            path: *mut u16,
            size: u32,
            flags: u32,
        ) -> u32;
        fn GetDriveTypeW(path: *const u16) -> u32;
        fn GetLastError() -> u32;
    }

    fn open(parent: *mut c_void, name: &std::ffi::OsStr) -> Result<File, String> {
        let mut wide: Vec<u16> = name.encode_wide().collect();
        if wide.is_empty() || wide.contains(&0) || wide.len() > 16_000 {
            return Err("Invalid local path.".into());
        }
        let mut unicode = UnicodeString {
            length: (wide.len() * 2) as u16,
            maximum_length: (wide.len() * 2) as u16,
            buffer: wide.as_mut_ptr(),
        };
        // OBJ_DONT_REPARSE rejects intermediate links as well as the final component.
        let mut attributes = ObjectAttributes {
            length: std::mem::size_of::<ObjectAttributes>() as u32,
            root: parent,
            name: &mut unicode,
            attributes: 0x40 | 0x1000,
            security: null_mut(),
            qos: null_mut(),
        };
        let mut status = IoStatus {
            status: 0,
            information: 0,
        };
        let mut handle = null_mut();
        let result = unsafe {
            NtCreateFile(
                &mut handle,
                0x0010_0089,
                &mut attributes,
                &mut status,
                null(),
                0,
                7,
                1,
                0x0020_0000 | 0x20,
                null(),
                0,
            )
        };
        if result < 0 {
            return Err("Path is inaccessible or traverses a link/reparse point.".into());
        }
        let file = unsafe { File::from_raw_handle(handle) };
        let mut tag = [0u32; 2];
        if unsafe {
            GetFileInformationByHandleEx(file.as_raw_handle(), 9, tag.as_mut_ptr().cast(), 8)
        } == 0
            || tag[0] & 0x400 != 0
        {
            return Err("Reparse points are not permitted.".into());
        }
        if tag[0] & 0x10 == 0 {
            let mut standard = [0u64; 4];
            if unsafe {
                GetFileInformationByHandleEx(
                    file.as_raw_handle(),
                    1,
                    standard.as_mut_ptr().cast(),
                    24,
                )
            } == 0
                || standard[2] as u32 > 1
            {
                return Err("Hard-linked or unverifiable regular files are not permitted.".into());
            }
        }
        Ok(file)
    }

    pub fn open_root(path: &Path) -> Result<(File, PathBuf), String> {
        if path.as_os_str().is_empty() {
            return Err("Choose an explicit local directory.".into());
        }
        if !path.is_absolute()
            && path
                .components()
                .any(|part| matches!(part, Component::Prefix(_) | Component::RootDir))
        {
            return Err(
                "Drive-relative and partially rooted Windows paths are not permitted.".into(),
            );
        }
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| "Cannot resolve the current directory.")?
                .join(path)
        };
        let mut normalized = PathBuf::new();
        for comp in absolute.components() {
            if !matches!(comp, Component::CurDir) {
                normalized.push(comp);
            }
        }
        let absolute = normalized;
        let Some(Component::Prefix(prefix)) = absolute.components().next() else {
            return Err("Only local disk directories are supported.".into());
        };
        let drive = match prefix.kind() {
            std::path::Prefix::Disk(drive) | std::path::Prefix::VerbatimDisk(drive) => drive,
            _ => return Err("Network/UNC and device paths are not permitted.".into()),
        };
        let disk = [drive as u16, b':' as u16, b'\\' as u16, 0];
        if !matches!(unsafe { GetDriveTypeW(disk.as_ptr()) }, 2 | 3) {
            return Err("Only local fixed/removable disks are supported.".into());
        }
        let mut normal = 0;
        for component in absolute.components() {
            match component {
                Component::ParentDir => {
                    return Err(
                        "Parent-directory components are not permitted; choose a canonical root."
                            .into(),
                    )
                }
                Component::Normal(name) => {
                    let text = name.to_string_lossy();
                    if text.eq_ignore_ascii_case(".git")
                        || text.contains(':')
                        || text.ends_with(['.', ' '])
                    {
                        return Err("Git metadata, alternate streams, and ambiguous Windows path names are not permitted.".into());
                    }
                    normal += 1;
                }
                _ => {}
            }
        }
        if normal == 0 {
            return Err("A whole disk is not a permitted project root.".into());
        }
        let path_text = absolute
            .to_str()
            .ok_or("The root path must be valid Unicode.")?;
        let disk_path = path_text.strip_prefix("\\\\?\\").unwrap_or(path_text);
        let nt_path = OsString::from(format!("\\??\\{disk_path}"));
        let file = open(null_mut(), &nt_path)?;
        if !file
            .metadata()
            .map_err(|_| "Cannot read root metadata.")?
            .is_dir()
        {
            return Err("The chosen root is not a directory.".into());
        }
        let mut final_path = vec![0u16; 32_768];
        let size = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle(),
                final_path.as_mut_ptr(),
                final_path.len() as u32,
                0,
            )
        };
        if size == 0 || size as usize >= final_path.len() {
            return Err("Cannot obtain the canonical local root.".into());
        }
        final_path.truncate(size as usize);
        let canonical = PathBuf::from(OsString::from_wide(&final_path));
        if canonical.components().any(
            |part| matches!(part, Component::Normal(name) if name.eq_ignore_ascii_case(".git")),
        ) {
            return Err("Git metadata is not a permitted canonical root.".into());
        }
        Ok((file, canonical))
    }

    pub fn open_child(parent: &File, name: &Path) -> Result<File, String> {
        let text = name.to_string_lossy();
        if text.contains([':', '\\', '/']) || text.ends_with(['.', ' ']) {
            return Err("Unsafe Windows entry name.".into());
        }
        open(parent.as_raw_handle(), name.as_os_str())
    }

    pub struct Entries<'a> {
        directory: &'a File,
        buffer: Vec<u64>,
        offset: Option<usize>,
        first: bool,
        ended: bool,
    }
    impl<'a> Entries<'a> {
        pub fn new(directory: &'a File) -> Result<Self, String> {
            Ok(Self {
                directory,
                buffer: vec![0; 8192],
                offset: None,
                first: true,
                ended: false,
            })
        }
        pub fn next_entry(&mut self) -> Option<Result<OsString, String>> {
            loop {
                if self.ended {
                    return None;
                }
                if self.offset.is_none() {
                    let class = if self.first { 11 } else { 10 };
                    self.first = false;
                    if unsafe {
                        GetFileInformationByHandleEx(
                            self.directory.as_raw_handle(),
                            class,
                            self.buffer.as_mut_ptr().cast(),
                            (self.buffer.len() * 8) as u32,
                        )
                    } == 0
                    {
                        self.ended = true;
                        return if unsafe { GetLastError() } == 18 {
                            None
                        } else {
                            Some(Err("Directory enumeration failed.".into()))
                        };
                    }
                    self.offset = Some(0);
                }
                let offset = self.offset.unwrap();
                let bytes = unsafe {
                    std::slice::from_raw_parts(
                        self.buffer.as_ptr().cast::<u8>(),
                        self.buffer.len() * 8,
                    )
                };
                let u32_at = |index| {
                    bytes
                        .get(index..index + 4)
                        .map(|v| u32::from_le_bytes(v.try_into().unwrap()))
                };
                let (Some(next), Some(length)) = (u32_at(offset), u32_at(offset + 60)) else {
                    self.ended = true;
                    return Some(Err("Invalid directory record.".into()));
                };
                if next != 0 && ((next as usize) < 104 || offset + next as usize >= bytes.len()) {
                    self.ended = true;
                    return Some(Err("Invalid directory record.".into()));
                }
                let Some(name) = bytes
                    .get(offset + 104..offset + 104 + length as usize)
                    .filter(|_| length % 2 == 0)
                else {
                    self.ended = true;
                    return Some(Err("Invalid directory name.".into()));
                };
                let wide: Vec<u16> = name
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_le_bytes([b[0], b[1]]))
                    .collect();
                self.offset = if next == 0 {
                    None
                } else {
                    Some(offset + next as usize)
                };
                let name = OsString::from_wide(&wide);
                if name == "." || name == ".." {
                    continue;
                }
                return Some(Ok(name));
            }
        }
    }
}

#[cfg(all(
    test,
    any(
        windows,
        all(
            target_os = "linux",
            any(target_arch = "x86_64", target_arch = "aarch64")
        )
    )
))]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::AtomicUsize;

    static NEXT_FIXTURE: AtomicUsize = AtomicUsize::new(0);

    struct Fixture(PathBuf);
    impl Fixture {
        fn new() -> Self {
            let base = std::env::temp_dir().join("bloomrepo-tests");
            fs::create_dir_all(&base).unwrap();
            assert!(base.is_dir(), "The approved fixture parent must exist");
            let path = base.join(format!(
                "analysis-fixture-{}-{}-{}",
                std::process::id(),
                chrono::Utc::now().timestamp_nanos_opt().unwrap(),
                NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
        fn write(&self, name: &str, text: &str) {
            let path = self.0.join(name);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, text).unwrap();
        }
        fn scan(&self) -> AnalysisReport {
            scan_local(&self.0, Arc::new(AtomicBool::new(false))).unwrap()
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    fn token() -> String {
        format!("ghp_{}", "A".repeat(36))
    }

    #[test]
    fn secrets_are_redacted_in_all_exports_and_env_is_scanned() {
        let f = Fixture::new();
        let github = token();
        let aws = format!("AKIA{}", "A".repeat(16));
        let header = "-----BEGIN RSA PRIVATE KEY-----";
        f.write(
            ".env",
            &format!("TOKEN={github}\nAWS={aws}\n{header}\nordinary user text=password\n"),
        );
        f.write(&format!("source-{github}.txt"), &github);
        let report = f.scan();
        assert_eq!(report.files_scanned, 2);
        assert_eq!(report.findings.len(), 4);
        for output in [
            serde_json::to_string(&report).unwrap(),
            report.markdown(),
            report.sbom_json().to_string(),
        ] {
            for secret in [&github, &aws, header] {
                assert!(!output.contains(secret), "secret leaked");
            }
            assert!(!output.contains("ordinary user text"));
        }
        assert!(report.findings.iter().all(|finding| finding.line.is_some()));
    }

    #[test]
    fn root_and_ancestor_credentials_are_redacted_without_changing_traversal() {
        let f = Fixture::new();
        let secret = token();
        for relative in [
            PathBuf::from(&secret),
            PathBuf::from(&secret).join("project"),
        ] {
            f.write(
                &relative.join("readme.txt").to_string_lossy(),
                "ordinary text",
            );
            let report =
                scan_local(&f.0.join(&relative), Arc::new(AtomicBool::new(false))).unwrap();
            assert_eq!(report.files_scanned, 1);
            assert!(report.root.contains("[REDACTED]"));
            for output in [
                report.root.clone(),
                serde_json::to_string(&report).unwrap(),
                report.markdown(),
            ] {
                assert!(!output.contains(&secret), "root credential leaked");
                assert!(
                    !output.contains(&markdown_text(&secret)),
                    "escaped root credential leaked"
                );
            }
        }
    }

    #[test]
    fn vcs_private_and_generated_paths_are_excluded() {
        let f = Fixture::new();
        for name in [
            ".git/config",
            ".private/data",
            "node_modules/pkg/a.js",
            "target/debug/a",
            "vendor/a",
            ".ssh/key",
        ] {
            f.write(name, &token());
        }
        f.write("readme.txt", "ordinary text");
        let report = f.scan();
        assert_eq!(report.files_scanned, 1);
        assert!(report.findings.is_empty());
        assert_eq!(report.skipped, 6);
        assert!(!report.coverage_gaps.is_empty());
    }

    #[test]
    fn parses_and_deduplicates_local_lockfiles() {
        let f = Fixture::new();
        f.write(
            "Cargo.lock",
            r#"version = 3
[[package]]
name = "serde"
version = "1.0.200"
source = "registry+https://github.com/rust-lang/crates.io-index"
[[package]]
name = "private-package"
version = "1.0.0"
source = "git+https://example.invalid/private"
"#,
        );
        f.write("package-lock.json", r#"{"lockfileVersion":3,"packages":{"":{"name":"root","version":"1.0.0"},"node_modules/left-pad":{"version":"1.3.0","resolved":"https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"},"node_modules/@scope/tool":{"version":"2.0.0"},"node_modules/link":{"link":true},"node_modules/private":{"version":"1.0.0","resolved":"https://private.invalid/pkg"}}}"#);
        f.write("nested/package-lock.json", r#"{"lockfileVersion":1,"dependencies":{"left-pad":{"version":"1.3.0","dependencies":{"inner":{"version":"2.1.0"}}}}}"#);
        f.write("requirements.txt", "Requests==2.31.0\nrequests==2.31.0\npackage>=1\n-r outside.txt\nDemo_Pkg==1.2.3 ; python_version > '3'\n");
        f.write(
            "uv.lock",
            r#"version = 1
[[package]]
name = "requests"
version = "2.31.0"
source = { registry = "https://pypi.org/simple" }
[[package]]
name = "project"
version = "1.0.0"
source = { editable = "." }
"#,
        );
        f.write(
            "pyproject.toml",
            r#"[project]
name = "demo"
dependencies = ["another==1.0.0", "unknown>=2"]
[project.optional-dependencies]
test = ["testing==3.0.0"]
"#,
        );
        let report = f.scan();
        assert_eq!(report.dependencies.len(), 8);
        assert!(report.dependencies.iter().any(|d| d.name == "@scope/tool"));
        assert!(report.dependencies.iter().any(|d| d.name == "demo-pkg"));
        assert!(!report
            .dependencies
            .iter()
            .any(|d| d.name == "root" || d.name == "private" || d.name == "private-package"));
        assert!(report.coverage_gaps.iter().any(|g| g.contains("Unpinned")));
        assert!(report
            .coverage_gaps
            .iter()
            .any(|g| g.contains("alternative")));
    }

    #[test]
    fn imports_spdx_cyclonedx_and_exports_valid_shape_and_purls() {
        let f = Fixture::new();
        f.write("sbom.cdx.json", r#"{"bomFormat":"CycloneDX","specVersion":"1.5","components":[{"type":"library","name":"@scope/tool","version":"1.2.0","purl":"pkg:npm/%40scope/tool@1.2.0","components":[{"purl":"pkg:cargo/serde@1.0.200"}]},{"name":"ambiguous","version":"1"}]}"#);
        f.write("sbom.spdx.json", r#"{"spdxVersion":"SPDX-2.3","packages":[{"name":"Requests","versionInfo":"2.31.0","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:pypi/Requests@2.31.0"}]},{"versionInfo":"9","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:npm/wrong@1.0.0"}]}]}"#);
        let report = f.scan();
        assert_eq!(report.dependencies.len(), 3);
        let sbom = report.sbom_json();
        assert_eq!(sbom["bomFormat"], "CycloneDX");
        assert_eq!(sbom["specVersion"], "1.5");
        assert_eq!(sbom["version"], 1);
        assert!(chrono::DateTime::parse_from_rfc3339(
            sbom["metadata"]["timestamp"].as_str().unwrap()
        )
        .is_ok());
        for component in sbom["components"].as_array().unwrap() {
            assert_eq!(component["type"], "library");
            assert!(parse_purl(component["purl"].as_str().unwrap()).is_some());
            assert!(component["bom-ref"]
                .as_str()
                .unwrap()
                .starts_with("dependency-"));
        }
        assert!(report
            .coverage_gaps
            .iter()
            .any(|g| g.contains("conflicting")));
    }

    #[test]
    fn ci_rules_distinguish_pinned_and_untrusted_contexts() {
        let f = Fixture::new();
        f.write(
            ".github/workflows/check.yml",
            &format!(
                r#"name: check
on:
  pull_request_target:
permissions: write-all
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - uses: owner/pinned@{}
      - uses: ./local-action
      - uses: docker://example@sha256:{}
      - run: |
          echo "${{{{ github.event.pull_request.title }}}}"
      - run: echo "$TITLE"
        env:
          TITLE: ${{{{ github.event.pull_request.title }}}}
"#,
                "a".repeat(40),
                "b".repeat(64)
            ),
        );
        let report = f.scan();
        for rule in [
            "ci.broad-write-permissions",
            "ci.mutable-action-reference",
            "ci.pull-request-target-untrusted-checkout",
            "ci.untrusted-run-interpolation",
        ] {
            assert_eq!(
                report.findings.iter().filter(|f| f.rule == rule).count(),
                1,
                "{rule}"
            );
        }
        assert_eq!(report.findings.len(), 4);
    }

    #[test]
    fn ci_comments_shell_literals_and_normal_checkout_do_not_claim_exploits() {
        let f = Fixture::new();
        f.write(
            ".github/workflows/check.yaml",
            &format!(
                r#"on: pull_request
# on: pull_request_target
# permissions: write-all
jobs:
  check:
    steps:
      - uses: actions/checkout@{}
        with:
          ref: ${{{{ github.event.pull_request.head.sha }}}}
      - run: |
          echo pull_request_target
          permissions: write-all
          uses: fake/action@v1
        env:
          TITLE: ${{{{ github.event.pull_request.title }}}}
"#,
                "a".repeat(40)
            ),
        );
        assert!(f.scan().findings.is_empty());
    }

    #[test]
    fn ci_run_block_shell_comments_are_checked_for_untrusted_interpolation() {
        for scalar in ["|", "|-", ">", ">+"] {
            let f = Fixture::new();
            f.write(
                ".github/workflows/check.yml",
                &format!(
                    "on: issues\njobs:\n  check:\n    steps:\n      - run: {scalar}\n          # ${{{{ github.event.issue.body }}}}\n          echo safe # ${{{{ github.event.issue.title }}}}\n"
                ),
            );
            let report = f.scan();
            assert_eq!(report.findings.len(), 2, "scalar {scalar}");
            for (finding, line) in report.findings.iter().zip([6, 7]) {
                assert_eq!(finding.rule, "ci.untrusted-run-interpolation");
                assert_eq!(finding.severity, "high");
                assert_eq!(finding.line, Some(line));
                assert!(finding
                    .evidence
                    .contains("exploitability is not established"));
            }
            for output in [serde_json::to_string(&report).unwrap(), report.markdown()] {
                assert!(!output.contains("github.event.issue"));
                assert!(!output.contains("echo safe"));
            }
        }
    }

    #[test]
    fn ci_yaml_comments_outside_run_scalars_do_not_flag_interpolation() {
        let f = Fixture::new();
        f.write(
            ".github/workflows/check.yml",
            r#"on: issues
jobs:
  check:
    steps:
      # - run: echo ${{ github.event.issue.body }}
      - run: echo safe # ${{ github.event.issue.body }}
      - run: | # ${{ github.event.issue.body }}
          echo safe
      # ${{ github.event.issue.body }}
      - run: echo safe
"#,
        );
        assert!(f.scan().findings.is_empty());
    }

    #[test]
    fn malformed_unsupported_and_secret_dependency_data_are_gaps() {
        let f = Fixture::new();
        f.write("Cargo.lock", "[[broken");
        f.write("package-lock.json", "{ nope");
        f.write(
            "requirements.txt",
            &format!(
                "{}==1.0.0\nthing==1.*\nthing @ https://example.invalid/x\n",
                token()
            ),
        );
        f.write("yarn.lock", "anything");
        f.write("sbom.xml", "<anything/>");
        f.write("sbom.json", &json!({"bomFormat": "CycloneDX", "components": [{"purl": format!("pkg:pypi/{}@1.0.0", token())}]}).to_string());
        let report = f.scan();
        assert!(report.dependencies.is_empty());
        assert!(report
            .coverage_gaps
            .iter()
            .any(|g| g.contains("could not be parsed")));
        assert!(report
            .coverage_gaps
            .iter()
            .any(|g| g.contains("unsupported dependency")));
        assert!(!serde_json::to_string(&report).unwrap().contains(&token()));
    }

    #[test]
    fn byte_and_depth_bounds_are_enforced() {
        let f = Fixture::new();
        f.write("too-large.txt", &"X".repeat(MAX_FILE_BYTES as usize + 1));
        let path = format!("{}secret.txt", "dir/".repeat(MAX_DEPTH + 1));
        f.write(&path, &token());
        let report = f.scan();
        assert!(report.findings.is_empty());
        assert!(report
            .coverage_gaps
            .iter()
            .any(|g| g.contains("byte budget")));
        assert!(report.coverage_gaps.iter().any(|g| g.contains("depth")));
    }

    fn scanner_for_bounds() -> Scanner {
        let f = Fixture::new();
        Scanner {
            report: f.scan(),
            rules: Rules::new(),
            dependencies: BTreeSet::new(),
            visited: 0,
            bytes: 0,
            started: Instant::now(),
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn count_total_time_dependency_and_finding_bounds_are_enforced() {
        let mut scanner = scanner_for_bounds();
        scanner.visited = MAX_ENTRIES;
        assert!(scanner.stopped());
        scanner.visited = 0;
        scanner.report.files_scanned = MAX_FILES;
        assert!(scanner.stopped());
        scanner.report.files_scanned = 0;
        scanner.bytes = MAX_TOTAL_BYTES;
        assert!(scanner.stopped());
        scanner.bytes = 0;
        scanner.started = Instant::now() - LOCAL_TIMEOUT;
        assert!(scanner.stopped());
        scanner.started = Instant::now();
        scanner.cancelled.store(true, Ordering::Relaxed);
        assert!(scanner.stopped());
        for index in 0..MAX_DEPENDENCIES + 1 {
            scanner.dependency("npm", &format!("pkg-{index}"), "1.0.0");
        }
        assert_eq!(scanner.dependencies.len(), MAX_DEPENDENCIES);
        for _ in 0..MAX_FINDINGS + 1 {
            scanner.finding("low", "test", "file", Some(1), "Fixed evidence", "Review");
        }
        assert_eq!(scanner.report.findings.len(), MAX_FINDINGS);
        assert!(scanner
            .report
            .coverage_gaps
            .iter()
            .any(|g| g.contains("dependency limit")));
        assert!(scanner
            .report
            .coverage_gaps
            .iter()
            .any(|g| g.contains("Finding limit")));
    }

    #[test]
    fn root_validation_rejects_files_git_empty_and_parent_components() {
        let f = Fixture::new();
        f.write("file.txt", "text");
        f.write(".git/config", "ignored");
        for path in [
            PathBuf::new(),
            f.0.join("file.txt"),
            f.0.join(".git"),
            f.0.join("../escape"),
        ] {
            assert!(scan_local(&path, Arc::new(AtomicBool::new(false))).is_err());
        }
        #[cfg(windows)]
        for path in [
            r"\\server\share",
            r"C:\",
            r"\\?\UNC\server\share",
            r"\\.\PhysicalDrive0",
        ] {
            assert!(scan_local(Path::new(path), Arc::new(AtomicBool::new(false))).is_err());
        }
        #[cfg(target_os = "linux")]
        assert!(scan_local(Path::new("/"), Arc::new(AtomicBool::new(false))).is_err());
    }

    #[test]
    fn symlinks_are_not_followed_even_inside_the_authorized_root() {
        let f = Fixture::new();
        let outside = Fixture::new();
        outside.write("secret.txt", &token());
        outside.write("subdir/secret.txt", &token());
        f.write("inside.txt", "safe");
        #[cfg(windows)]
        {
            use std::os::windows::fs::{symlink_dir, symlink_file};
            // Windows may require Developer Mode or elevated link privileges.
            if symlink_dir(&outside.0, f.0.join("linked-dir")).is_err() {
                eprintln!("SKIPPED symlink fixture: Windows link privileges unavailable.");
                return;
            }
            symlink_file(outside.0.join("secret.txt"), f.0.join("linked-file")).unwrap();
            symlink_file(f.0.join("inside.txt"), f.0.join("internal-link")).unwrap();
        }
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::symlink;
            symlink(&outside.0, f.0.join("linked-dir")).unwrap();
            symlink(outside.0.join("secret.txt"), f.0.join("linked-file")).unwrap();
            symlink(f.0.join("inside.txt"), f.0.join("internal-link")).unwrap();
        }
        let report = f.scan();
        assert_eq!(report.files_scanned, 1);
        assert!(report.findings.is_empty());
        assert_eq!(report.skipped, 3);
        assert!(scan_local(&f.0.join("linked-dir"), Arc::new(AtomicBool::new(false))).is_err());
        assert!(scan_local(
            &f.0.join("linked-dir/subdir"),
            Arc::new(AtomicBool::new(false))
        )
        .is_err());
    }

    #[cfg(windows)]
    #[test]
    fn junctions_are_not_followed_as_entries_roots_or_root_ancestors() {
        use std::ffi::c_void;
        use std::os::windows::ffi::OsStrExt;
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn DeviceIoControl(
                handle: *mut c_void,
                code: u32,
                input: *const c_void,
                input_size: u32,
                output: *mut c_void,
                output_size: u32,
                returned: *mut u32,
                overlapped: *mut c_void,
            ) -> i32;
        }
        let f = Fixture::new();
        let outside = Fixture::new();
        outside.write("subdir/secret.txt", &token());
        f.write("safe.txt", "safe");
        let junction = f.0.join("junction");
        fs::create_dir(&junction).unwrap();
        let handle = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(0x02000000 | 0x00200000)
            .open(&junction)
            .unwrap();
        let substitute: Vec<u16> = format!("\\??\\{}", outside.0.display())
            .encode_utf16()
            .collect();
        let print: Vec<u16> = outside.0.as_os_str().encode_wide().collect();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&0xA0000003u32.to_le_bytes());
        buffer.extend_from_slice(
            &(8u16 + ((substitute.len() + print.len() + 2) * 2) as u16).to_le_bytes(),
        );
        buffer.extend_from_slice(&0u16.to_le_bytes());
        for value in [
            0,
            (substitute.len() * 2) as u16,
            ((substitute.len() + 1) * 2) as u16,
            (print.len() * 2) as u16,
        ] {
            buffer.extend_from_slice(&value.to_le_bytes());
        }
        for word in substitute.into_iter().chain([0]).chain(print).chain([0]) {
            buffer.extend_from_slice(&word.to_le_bytes());
        }
        let mut returned = 0;
        let success = unsafe {
            DeviceIoControl(
                handle.as_raw_handle(),
                0x000900A4,
                buffer.as_ptr().cast(),
                buffer.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(
            success,
            0,
            "Could not create the junction fixture: {}",
            std::io::Error::last_os_error()
        );
        drop(handle);
        let report = f.scan();
        assert_eq!(report.files_scanned, 1);
        assert!(report.findings.is_empty());
        assert_eq!(report.skipped, 1);
        for path in [&junction, &junction.join("subdir")] {
            assert!(scan_local(path, Arc::new(AtomicBool::new(false))).is_err());
        }
        fs::remove_dir(&junction).unwrap();
        assert!(outside.0.join("subdir/secret.txt").is_file());
    }

    #[test]
    fn hard_links_are_skipped_without_reading_contents() {
        let f = Fixture::new();
        let outside = Fixture::new();
        outside.write("secret.txt", &token());
        fs::hard_link(outside.0.join("secret.txt"), f.0.join("linked.txt")).unwrap();
        let report = f.scan();
        assert_eq!(report.files_scanned, 0);
        assert_eq!(report.skipped, 1);
        assert!(report.findings.is_empty());
    }

    #[test]
    fn osv_response_never_copies_source_text_or_infers_severity() {
        let f = Fixture::new();
        let mut report = f.scan();
        let dep = Dependency {
            ecosystem: "npm".into(),
            name: "demo".into(),
            version: "1.2.3".into(),
        };
        let rules = Rules::new();
        apply_osv_response(
            &mut report,
            &dep,
            &json!({"vulns": [
                {"id": "GHSA-1234-abcd-5678", "summary": token(), "severity": [{"type":"CVSS_V3", "score":"10"}]},
                {"id": "CVE-2024-0001", "withdrawn": "2024-01-01T00:00:00Z"},
                {"id": token()}, {"id": "<unsafe>"}
            ]}),
            &rules,
        );
        assert_eq!(report.findings.len(), 1);
        assert_eq!(report.findings[0].severity, "unknown");
        assert!(report.findings[0].evidence.contains("GHSA-1234-abcd-5678"));
        assert!(!serde_json::to_string(&report).unwrap().contains(&token()));
        apply_osv_response(&mut report, &dep, &json!({"vulns": "invalid"}), &rules);
        apply_osv_response(&mut report, &dep, &json!({"error": token()}), &rules);
        assert!(report
            .coverage_gaps
            .iter()
            .any(|g| g.contains("unsupported vulnerability list")));
        assert!(report
            .coverage_gaps
            .iter()
            .any(|g| g.contains("returned an error")));
        apply_osv_response(&mut report, &dep, &json!({}), &rules);
        assert_eq!(report.findings.len(), 1);
    }

    #[tokio::test]
    async fn public_offline_api_reports_no_network_and_supports_old_serialization() {
        let f = Fixture::new();
        f.write("requirements.txt", "demo==1.2.3\n");
        let report = analyze_directory(&f.0, false).await.unwrap();
        assert!(!report.osv_requested);
        assert_eq!(report.osv_queries, 0);
        assert!(report.markdown().contains("Offline"));
        assert!(report.markdown().contains("not proof"));
        let mut serialized = serde_json::to_value(report).unwrap();
        for key in ["coverage_gaps", "osv_requested", "osv_queries"] {
            serialized.as_object_mut().unwrap().remove(key);
        }
        let old: AnalysisReport = serde_json::from_value(serialized).unwrap();
        assert!(old.coverage_gaps.is_empty());
        assert!(!old.osv_requested);
        assert_eq!(old.osv_queries, 0);
    }

    #[test]
    fn purl_and_markdown_input_validation() {
        let dep = Dependency {
            ecosystem: "npm".into(),
            name: "@scope/tool".into(),
            version: "1.2.3+build".into(),
        };
        let purl = dependency_purl(&dep).unwrap();
        assert_eq!(purl, "pkg:npm/%40scope/tool@1.2.3%2Bbuild");
        assert_eq!(parse_purl(&purl).unwrap(), dep);
        for purl in [
            "pkg:npm/tool@https://evil",
            "pkg:npm/tool@1.*",
            "pkg:cargo/tool@1.0.0?repository_url=bad",
            "pkg:generic/a@1",
            "pkg:npm/%ZZ@1",
        ] {
            assert!(parse_purl(purl).is_none());
        }
        assert_eq!(
            markdown_text("<script>|[x]`\n"),
            "&lt;script&gt;\\|\\[x\\]\\` "
        );
    }

    #[test]
    fn growing_files_and_remaining_total_budget_do_not_bypass_limits() {
        let f = Fixture::new();
        f.write("growing.txt", &"X".repeat(MAX_FILE_BYTES as usize + 100));
        let mut scanner = scanner_for_bounds();
        scanner.scan_file(
            File::open(f.0.join("growing.txt")).unwrap(),
            Path::new("growing.txt"),
            0,
        );
        assert_eq!(scanner.report.files_scanned, 0);
        assert_eq!(scanner.report.skipped, 1);
        assert_eq!(scanner.bytes, MAX_FILE_BYTES + 1);
        scanner.bytes = MAX_TOTAL_BYTES - 10;
        f.write("budget.txt", "twenty bytes of data!");
        scanner.scan_file(
            File::open(f.0.join("budget.txt")).unwrap(),
            Path::new("budget.txt"),
            20,
        );
        assert_eq!(scanner.report.files_scanned, 0);
        assert_eq!(scanner.report.skipped, 2);
        assert_eq!(scanner.bytes, MAX_TOTAL_BYTES - 10);
    }
}

#[cfg(all(
    target_os = "linux",
    any(target_arch = "x86_64", target_arch = "aarch64")
))]
mod secure_fs {
    use super::*;
    use std::ffi::{c_char, c_int, c_long, c_void, CString, OsString};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::{AsRawFd, FromRawFd};
    unsafe extern "C" {
        fn openat(fd: c_int, path: *const c_char, flags: c_int, ...) -> c_int;
        fn fstatfs(fd: c_int, buffer: *mut c_void) -> c_int;
        fn syscall(number: c_long, ...) -> c_long;
    }
    fn open(parent: &File, name: &Path) -> Result<File, String> {
        let name = CString::new(name.as_os_str().as_bytes()).map_err(|_| "Invalid path.")?;
        #[repr(C)]
        struct OpenHow {
            flags: u64,
            mode: u64,
            resolve: u64,
        }
        // O_PATH does not open devices/FIFOs for I/O. openat2 also rejects all mount crossings,
        // including same-device bind mounts, and requires Linux 5.6+ (no weaker fallback).
        let how = OpenHow {
            flags: 0x200000 | 0x20000 | 0x80000,
            mode: 0,
            resolve: 0x08 | 0x04 | 0x01,
        };
        let fd = unsafe {
            syscall(
                437,
                parent.as_raw_fd(),
                name.as_ptr(),
                &how as *const OpenHow,
                std::mem::size_of::<OpenHow>(),
            )
        };
        if fd < 0 {
            return Err("Unsafe or inaccessible entry.".into());
        }
        let file = unsafe { File::from_raw_fd(fd as c_int) };
        let metadata = file.metadata().map_err(|_| "Cannot read entry metadata.")?;
        if !metadata.is_file() && !metadata.is_dir() {
            return Err("Non-regular entry.".into());
        }
        // Reject mounts into another filesystem (including bind mounts with another device).
        use std::os::unix::fs::MetadataExt;
        if metadata.is_file() && metadata.nlink() > 1 {
            return Err("Hard-linked regular files are not permitted.".into());
        }
        if metadata.dev()
            != parent
                .metadata()
                .map_err(|_| "Cannot read parent metadata.")?
                .dev()
        {
            return Err("Filesystem boundary crossing is not permitted.".into());
        }
        if metadata.is_file() {
            File::open(format!("/proc/self/fd/{}", file.as_raw_fd()))
                .map_err(|_| "Cannot read the safely opened regular file.".into())
        } else {
            Ok(file)
        }
    }
    pub fn open_root(path: &Path) -> Result<(File, PathBuf), String> {
        if path.as_os_str().is_empty() {
            return Err("Choose an explicit local directory.".into());
        }
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()
                .map_err(|_| "Cannot resolve the current directory.")?
                .join(path)
        };
        let mut directory = File::open("/").map_err(|_| "Cannot open local filesystem root.")?;
        let mut canonical = PathBuf::from("/");
        for component in absolute.components() {
            match component {
                Component::Normal(name) => {
                    if name.eq_ignore_ascii_case(".git") {
                        return Err("Git metadata is not a permitted root.".into());
                    }
                    // Root selection may cross a mount, but later traversal may not.
                    let name_c =
                        CString::new(name.as_bytes()).map_err(|_| "Invalid local path.")?;
                    let fd = unsafe {
                        openat(
                            directory.as_raw_fd(),
                            name_c.as_ptr(),
                            0x20000 | 0x80000 | 0x10000 | 0x800,
                        )
                    };
                    if fd < 0 {
                        return Err("Root is not a directory or traverses a symlink.".into());
                    }
                    directory = unsafe { File::from_raw_fd(fd) };
                    canonical.push(name);
                }
                Component::ParentDir => {
                    return Err(
                        "Parent-directory components are not permitted; choose a canonical root."
                            .into(),
                    )
                }
                _ => {}
            }
        }
        if canonical == Path::new("/") {
            return Err("A whole filesystem is not a permitted project root.".into());
        }
        // Linux statfs starts with a native long; oversized aligned storage avoids ABI-size assumptions.
        let mut fs = [0usize; 64];
        if unsafe { fstatfs(directory.as_raw_fd(), fs.as_mut_ptr().cast()) } != 0 {
            return Err("Cannot verify the local filesystem.".into());
        }
        // Fail closed on unknown/network/FUSE filesystems. These are common local disk/tmp filesystems.
        if !matches!(
            fs[0],
            0xEF53
                | 0x58465342
                | 0x9123683E
                | 0x01021994
                | 0x858458F6
                | 0x794C7630
                | 0x2FC12FC1
                | 0x4D44
                | 0x2011BAB0
        ) {
            return Err(
                "This filesystem is not in the supported local filesystem allowlist.".into(),
            );
        }
        // Probe required openat2 support before claiming this platform can safely scan.
        open(&directory, Path::new("."))?;
        Ok((directory, canonical))
    }
    pub fn open_child(parent: &File, name: &Path) -> Result<File, String> {
        open(parent, name)
    }
    pub struct Entries {
        entries: std::fs::ReadDir,
    }
    impl Entries {
        pub fn new(directory: &File) -> Result<Self, String> {
            // This trusted procfs fd link refers to our open directory, not a repository pathname.
            let entries = std::fs::read_dir(format!("/proc/self/fd/{}", directory.as_raw_fd()))
                .map_err(|_| "Cannot enumerate the open directory.")?;
            Ok(Self { entries })
        }
        pub fn next_entry(&mut self) -> Option<Result<OsString, String>> {
            self.entries.next().map(|entry| {
                entry
                    .map(|entry| entry.file_name())
                    .map_err(|_| "Directory enumeration failed.".into())
            })
        }
    }
}

#[cfg(not(any(
    windows,
    all(
        target_os = "linux",
        any(target_arch = "x86_64", target_arch = "aarch64")
    )
)))]
mod secure_fs {
    use super::*;
    use std::ffi::OsString;
    pub fn open_root(_: &Path) -> Result<(File, PathBuf), String> {
        Err(
            "Secure local traversal requires Windows or Linux x86_64/aarch64 (5.6+ with procfs)."
                .into(),
        )
    }
    pub fn open_child(_: &File, _: &Path) -> Result<File, String> {
        Err("Unsupported platform.".into())
    }
    pub struct Entries;
    impl Entries {
        pub fn new(_: &File) -> Result<Self, String> {
            Err("Unsupported platform.".into())
        }
        pub fn next_entry(&mut self) -> Option<Result<OsString, String>> {
            None
        }
    }
}
