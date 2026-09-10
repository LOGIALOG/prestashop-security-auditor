# Night execution plan

Date: 2026-09-06
Release constraint: no remote push or publication without explicit approval.

## Outcome for tonight

Produce a locally verified public-release candidate with a trustworthy advisory supply chain, a useful developer workflow and no bundled real-shop data.

## Phase 1 — Repository safety gate

- [x] Verify that no real client domain, report, database, credential or captured response is tracked.
- [x] Add automated repository-content checks for prohibited real-domain fixtures and generated reports.
- [x] Review `.gitignore` for reports, databases, exports, environment files and local scan output.
- [x] Confirm the demo remains restricted to `demo.local` with a permanent watermark.

Exit gate: repository scan reports no real-shop data or secrets.

## Phase 2 — Local source integrity

- [x] Add checksum comparison against a user-supplied official PrestaShop/module ZIP archive.
- [x] Keep comparison read-only and offline; never execute archive content.
- [x] Report missing and modified files without exporting their contents.
- [x] Add bounded detection of locally added code files.
- [x] Reject archive path traversal, symlinks and oversized/unbounded inputs.

Exit gate: positive, tampered and unsafe-archive fixtures pass their expected tests.

## Phase 3 — Advisory supply chain

- [x] Add review-candidate adapters for Friends of Presta and official PrestaShop payloads.
- [x] Separate normalization and review; imported data never becomes trusted automatically.
- [x] Generate a pending review document without modifying the trusted advisory directory.
- [x] Document provenance conflict handling and the manual promotion workflow.

Exit gate: offline normalization fixtures are deterministic and malformed upstream data is rejected.

## Phase 4 — Developer and CI experience

- [x] Add CLI contract tests for successful scans, network failures and `--fail-on-confirmed`.
- [x] Add a safe CI repository-content gate.
- [x] Validate JSON, SARIF and CycloneDX compatibility contracts.
- [x] Improve CLI output encoding and concise error messages on Windows.

Exit gate: backend tests, frontend tests, production build and advisory validation all pass.

## Phase 5 — Public repository readiness

- [x] Add `CONTRIBUTING.md`, code of conduct and issue templates for bugs and advisory proposals.
- [x] Add the owner-approved Apache License 2.0 text and LOGIALOG attribution notice.
- [x] Review README quick start and responsible-disclosure flow.
- [x] Produce a local release checklist and proposed commit breakdown.

Exit gate: release checklist is complete except for owner decisions and explicit push approval.

## Explicitly out of scope tonight

- External scans of real shops.
- Exploit payloads, brute force or bypass testing.
- Automatic trust of remotely fetched advisories.
- Cloud deployment, telemetry or user accounts.
- Git commit, remote push, release or package publication without explicit approval.

## Proposed commit sequence

1. `fix: prevent real audit artifacts from entering the repository`
2. `feat: compare local PrestaShop files with trusted archives`
3. `feat: add review-only advisory ingestion adapters`
4. `refactor: enforce CLI and export compatibility contracts`
5. `feat: add public contribution and disclosure workflows`
