# Security Policy

## Reporting

Report suspected vulnerabilities privately to [contact@guiarx.com](mailto:contact@guiarx.com), or [hello@guiarx.com](mailto:hello@guiarx.com). Include the commit/version, operating system, relevant configuration with secrets removed, reproduction steps, and expected versus observed behavior. Do not include live tokens, private source, full databases, or unredacted reports. Avoid publishing exploit details in a public issue before coordination.

These are the author's existing contact addresses, not a promise of encrypted intake, response deadlines, a bounty, or long-term support for older releases. This document describes the current v3 implementation; no security certification is asserted. Confirm fixes against the specific revision you run.

## Trust Boundaries

BloomRepo stores data locally, but discovery is a network operation. It uses no AI services. Do not infer complete privacy, complete GitHub coverage, or repository safety from local storage or an empty analysis report.

| Operation | Data and destination |
| --- | --- |
| Discovery, enrichment, watch refresh | Queries/repository identifiers and configured authentication go to GitHub's public REST API. The engine excludes private observations from public discovery/delivery; do not grant unnecessary private-repository access. |
| Discord/Telegram/custom webhook | Configured channels receive repository metadata. Webhook URLs, bot tokens, and chat IDs are secrets. Unconfigured external channels are disabled. |
| Local static analysis | Reads the explicitly authorized local project. Findings, paths, dependency inventory, limits, and gaps may be stored in SQLite and exported locally; project files are not modified. |
| OSV, only with separate opt-in | Validated dependency names, versions, and ecosystems go to `https://api.osv.dev/v1/query`. Source contents and file paths are not part of the request. Dependency identities can themselves be sensitive. |
| Windows toast | Optional, Windows-only local notification through a fixed PowerShell script. Repository text is passed as data, not executable script source. |
| Open repository/contact links | Explicit GUI actions hand validated repository links or fixed author contacts to the system browser/mail handler, outside BloomRepo's network controls. |
| CI, if run remotely | GitHub runners fetch toolchains/crates/advisories and process the checked-out project. Artifact upload requires explicit manual opt-in; this is separate from local application operation. |

## Credentials And Storage

- Use the least GitHub permissions needed for public metadata. Revoke and rotate exposed credentials; deleting a file does not remove secrets from history, logs, or backups.
- Keep secret values in the process environment or a private `.env` beside the selected config. The environment overrides `.env`, including empty values; plural `GITHUB_TOKENS` wins over singular `GITHUB_TOKEN` within a layer. Never commit inline credentials or a populated `.env`.
- Config debug output redacts credential fields and config serialization omits them. Serialization is not a lossless save format. Redaction covers implemented paths and patterns, not every possible sensitive value or third-party diagnostic.
- SQLite, output shards, reports, legacy state, and backups are **not encrypted by BloomRepo**. Protect them with filesystem permissions and, where appropriate, disk encryption. Reports retain paths and package identities even though matched secret values and source snippets are omitted.
- Use a private local data directory, without symlink/junction ancestors. Relative storage paths are based on the working directory. Database instance locking prevents cooperating BloomRepo processes from sharing one database, not arbitrary programs or a compromised local account.
- Do not treat the application as a sandbox against administrators, hostile local processes, modified binaries, or untrusted storage directories. Files can change while work is in progress; filesystem/hardware synchronization behavior still matters.

## Network Destinations

Notification endpoints must use public HTTPS, with no URL userinfo or fragment. Syntax validation rejects localhost/private address destinations; delivery also checks all resolved addresses and pins the checked public answer. Redirects and proxy discovery are disabled for notification delivery. Mixed public/private DNS answers are rejected. These restrictions intentionally exclude internal/loopback webhook receivers; do not suggest bypassing them to make an example work.

Offline `--validate-config` validates syntax and rules, not reachability, DNS answers, token validity, quotas, or receiver semantics. OSV requests are explicit, bounded, HTTPS-only, and do not follow redirects or discover proxies. These controls are not a general guarantee about the behavior of third-party services or browser links.

## Durable Delivery

Cycle observations, cursor/state changes, and outbox entries are committed together in SQLite with `synchronous=FULL`. This avoids advancing discovery state without persisting the associated observations and delivery intent. It does not make a remote request part of that transaction.

Remote notifications use **at-least-once retry semantics**. A receiver can accept a request before a crash or timeout prevents recording success locally, so a retry can repeat the effect. The custom webhook includes a stable `Idempotency-Key` header and JSON `idempotency_key`. The receiver must persistently deduplicate the key before applying side effects. Discord, Telegram, and toasts do not provide BloomRepo-managed exactly-once delivery. Bounded retries can end in failed rows requiring operator recovery; at-least-once semantics is not a promise of eventual success.

The continuous dispatcher is independent of discovery. One-shot mode attempts one bounded pass, not a complete drain; budgets, backoff, disabled channels, and failures may leave queued work. Check `--health`, use `--retry-notifications` after correcting a failed destination, or resume continuous mode. Disabling a channel does not prove old queued records have disappeared.

Local log/JSONL delivery uses stable event shards under `outputs/YYYY-MM/` beside the database. Replays verify existing content rather than append duplicates. A conflict fails rather than overwrites. Legacy monthly aggregate files remain untouched. These file semantics do not transfer to remote receivers.

## Authorized Analysis

Analyze only a project you own or have permission to inspect. The CLI requires `--authorized`; the GUI requires authorization confirmation. OSV has separate consent and is off by default. No repository code, hooks, Git commands, dependency installers, or package managers are executed by the analyzer. Read-only analysis still writes its report to the configured database and optionally creates explicit exports; place exports outside the selected tree.

Secure traversal is implemented for Windows and Linux x86_64/aarch64 (kernel 5.6+ with procfs and `openat2`). Windows accepts local fixed/removable disks, not UNC/device roots; Linux accepts only the implemented local filesystem allowlist and rejects unknown/network/FUSE filesystems. Other platforms fail closed. Whole disks/filesystems, Git metadata roots, and parent-directory path components are not permitted. Traversal skips links, junctions/reparse points, hard-linked regular files, non-regular files, and Linux mount crossings.

Hidden/generated/vendor entries are generally excluded; `.github`, `.env`, and `.env.*` are hidden-entry exceptions. Binary/non-UTF-8 files are not statically analyzed. Skipped or inaccessible entries and unsupported formats reduce coverage and are reported as gaps.

| Resource | Bound |
| --- | --- |
| Local traversal | 10,000 files, 30,000 entries, depth 24, 1 MiB per file, 50 MiB total, 20 seconds cooperative work. |
| Findings/inventory | 1,000 findings and 5,000 unique dependencies. |
| OSV | At most 100 sequential queries within 30 seconds; individual requests and responses are bounded. |

Synchronous filesystem calls cannot be forcibly interrupted, so cancellation/timeouts are cooperative and a stalled call can outlive them. Files can change during a scan; the report is not a filesystem snapshot.

Secret recognition covers selected token/access-key/private-key patterns, not arbitrary credentials or their validity. GitHub Actions checks are conservative line/indentation heuristics, not a full YAML/expression interpreter; aliases, dynamic values, and reusable workflows may be missed. Dependency inventory is partial, does not resolve/install packages or evaluate licenses, and cannot establish actual deployed versions. Imported SBOM declarations are unverified.

An exported CycloneDX 1.5 inventory is not a complete supply-chain attestation. OSV lookup failures and limits mean incomplete vulnerability coverage; offline mode provides no known-vulnerability lookup. **No findings, a low score, or no OSV matches does not establish that a project is safe.**

## Migration And Recovery

Supported database schemas migrate automatically after a SQLite online backup of an existing nonempty database. The backup includes committed WAL pages and is written beside the database. Manual `--backup` uses SQLite's backup facility, creates a standalone new file, and never overwrites an existing destination. Restrict backup access just like the original database; configuration, legacy sidecar, and separate outputs are not included.

SQLite is authoritative for engine state. Legacy `_state.json` is considered only when no state exists in SQLite, and becomes durable on the first committed cycle. Once state is stored, the sidecar is not the active checkpoint. Corrupt/unsupported persisted state causes an error rather than silent cursor reset. Preserve evidence and backups before repair; do not delete state or copy only an active database's `.db` file to conceal a problem.

GitHub event feeds are bounded, Search is eventually indexed and capped, and sequential discovery covers only the verified ID anchor onward. Saturated/unsplittable search windows retain a coverage gap rather than advance as if complete. These limitations also apply when evaluating whether a repository was observed at a particular time.

## CI And Artifacts

The workflow uses read-only repository permissions, non-persisted checkout credentials, immutable action SHAs, locked Cargo operations, and a pinned `cargo-audit` install. Auditing covers the full lockfile and denies warnings without blanket waivers or target exclusions. Review advisories and upgrade dependencies deliberately; a passing audit only describes known advisory coverage at that time.

Quality checks are configured for Ubuntu and Windows. Source-side compilation, formatting, lints, advisory findings, or nonportable test fixtures can block CI; this policy does not assert that the current revision passes. Stable Rust, runner images, and advisory data remain moving inputs.

The gated Windows build prepares an unsigned executable, a SHA-256 checksum, self-reported build information, and Cargo metadata JSON. Cargo metadata is an inventory, **not a standard SBOM**. Checksums detect mismatches relative to a trusted expected hash; an attacker who replaces both files can defeat that check. Build information is **not signed provenance, an attestation, or a reproducible-build guarantee**. Artifact upload is manual opt-in only; no release publishing, signing, or AI integration is configured.
