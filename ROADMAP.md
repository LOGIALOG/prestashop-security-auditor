# Product roadmap

The roadmap preserves one invariant: a real finding cannot exist without recorded evidence.

The current implementation sequence and release gates are tracked in [docs/NIGHT_PLAN.md](docs/NIGHT_PLAN.md).

## v1.1 — Developer workflow

- [x] Portable JSON export without local filesystem paths.
- [x] SARIF 2.1.0 export with evidence URL, timestamp, response hash, confidence and detection method.
- [x] Add JSON/SARIF download actions to the report screen.
- [x] Add a CLI with `scan`, `export` and `advisories validate` commands.
- [x] Define stable CLI exit codes and a confirmed-finding threshold.
- [x] Document private authorized SARIF upload and add a no-scan CI workflow.
- [x] Add an export contract and compatibility tests.

Exit criteria: an authorized audit can run headlessly and publish reproducible findings to a CI pipeline.

## v1.2 — Trust and advisory supply chain

- [x] Validate every bundled advisory record with strict typed schemas.
- [x] Add an explicit advisory schema version.
- [x] Document the advisory schema migration policy.
- [x] Store record ID, source authority, source URL, publication/retrieval dates and affected ranges.
- [x] Produce a deterministic SHA-256 advisory snapshot manifest.
- [x] Add Ed25519 signing and public-key verification for released manifests.
- [x] Add review-only Friends of Presta and official PrestaShop normalization adapters.
- [x] Create positive and negative regression fixtures for every remote extractor.
- [x] Add audit-to-audit diff for real audits only.

Exit criteria: the origin of every rule and every change is reviewable offline.

## v1.3 — Trusted local source scan

- [x] Scan a user-selected local checkout without network access or code execution.
- [x] Inventory core, module and Composer package versions.
- [x] Inventory overrides and safe configuration/deployment flags without collecting secrets.
- [x] Compare checksums with user-supplied official ZIP archives.
- [x] Export a CycloneDX 1.6 SBOM.
- [x] Detect conservative PHP review signals with file/line evidence and documented confidence.

Exit criteria: developers can move from a passive signal to a precise local remediation location.

## v1.4 — Agency and community edition

- [x] English, French and Arabic UI strings, including RTL layout and versioned locale persistence.
- [x] Reusable validated white-label report profile while keeping immutable LOGIALOG provenance in metadata.
- [x] Explicit multistore inventory with isolated per-shop scope, evidence and request budgets.
- [x] Explicit opt-in extractor SDK 1.0, validated signal schema and contribution fixture guide.
- [x] Add responsible-disclosure guidance and safe bug, advisory and extractor issue templates.
- [x] Chromium accessibility and responsive regression suite for keyboard focus, FR/AR, RTL and mobile overflow.

Exit criteria: agencies and community contributors can extend the tool without weakening its evidence policy.

## Later, after validation

- [x] Scheduler-friendly local monitoring with quiet baselines and meaningful-change exit signalling.
- [x] Optional PrestaShop companion module with HTTPS timestamped-HMAC read-only inventory.
- [x] Local append-only team history with attributed review events and a verifiable SHA-256 chain.
- [x] Deterministic signed report bundles with in-memory verification.
- [x] Versioned policy packs that evaluate audits without changing findings or scores.

These items should follow real user feedback; they are not required for the first public release.

## v2.0 — Offline local advisory assessment

- [x] Hash the exact local metadata file used as version evidence, including the PrestaShop 9 install-version source.
- [x] Correlate locally detected module versions with a manifest-verified advisory snapshot without network or code execution.
- [x] Keep affected, not-affected and indeterminate states explicit; never present version correlation as exploitation evidence.
- [x] Report core security releases as maintenance guidance instead of unsupported CVE claims.
- [x] Export local paths and provenance in JSON, SARIF 2.1.0 and CycloneDX 1.6.
- [x] Add a CI-friendly `--fail-on-affected` threshold with regression tests for fixed, affected, unknown and tampered inputs.

Exit criteria: a developer can turn a trusted checkout into an offline, reviewable remediation queue without overstating certainty.

## v2.1 — Predictable operation

- [x] Add a network-free `doctor` report for required local integrity checks and optional runtimes.
- [x] Add an authorization-gated scan plan that previews fixed URLs, same-origin policy, methods, delay and request budget without network access.
- [x] Accept explicit repeated public pages consistently in the plan and the real scan CLI.
- [x] Define stable machine-readable contracts and a dedicated readiness exit code.

Exit criteria: operators can verify readiness and exact scan boundaries before the first request leaves the machine.
