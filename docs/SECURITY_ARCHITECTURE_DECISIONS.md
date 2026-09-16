# Security architecture decision record

Status date: 2026-09-16

This document is the durable decision memory for LOGIALOG PrestaShop Security Auditor. It records security doctrine, evidence-review rules, validation lessons, current runtime contracts, the delivery gate and the advisory-ingestion direction. It is not a product claim, an implementation specification or authorization to access a real shop.

> Provenance note: this record is a hash-verified reconstruction. Its textual base is the recovered decision record (SHA256 `9a58c3b612ea086de947c5291ef5df25613ef8f1b6056e800f25c3e85d0dd857`). The historical commit `5b960b08...` is unrecovered and MUST NOT be represented as the canonical implementation commit. Statements below were reconciled against current `origin/main`.

## 1. Status and authority

The labels below are normative throughout this record:

- **CANONICAL**: present on `origin/main` and supported by the repository's current contracts.
- **PROVEN**: supported by reproducible evidence within the stated scope. It does not imply ecosystem-wide validity.
- **PROPOSED**: architectural direction requiring a dedicated reviewed gate before implementation.
- **FUTURE**: sequenced work that is not part of the current implementation gate.
- **OPEN DECISION**: intentionally unresolved; no implementation may silently choose an answer.

### Canonical baseline

**CANONICAL** — `origin/main` is commit `be94954a4f27463e094cd30e5561f0c094e7c6a9` (merge of pull request #7, scan-completeness P2 hardening), preceded by `ffd8542c15a4f1dc34a5a2fb650471cf6d23829a` (merge of pull request #6, synthetic scan-completeness). The scan-completeness and false-PASS hardening work is now merged and canonical. The exact current rules remain defined by [VALIDATION_PROTOCOL.md](VALIDATION_PROTOCOL.md), [VALIDATION_GOVERNANCE.md](VALIDATION_GOVERNANCE.md), [ADVISORY_REVIEW.md](ADVISORY_REVIEW.md) and [ADVISORY_SCHEMA.md](ADVISORY_SCHEMA.md).

### Historical provenance

The historical commit `5b960b08...` referenced by earlier notes is unrecovered and is not present on `origin/main`. It is recorded here only as unrecovered historical provenance and must not be cited as the canonical implementation commit. The canonical merge lineage above is authoritative.

### Future advisory ingestion

**PROPOSED** — The reviewed external advisory ingestion design in this record has not been implemented or frozen as a schema. Current manual local proposal and signed-snapshot behavior remains canonical.

## 2. Core security doctrine

The following invariants apply to design, implementation, testing and review:

- **NO EVIDENCE != PASS** — absence of evidence cannot establish a safe condition.
- **FAILED OBSERVATION != SAFE OBSERVATION** — transport, parsing or execution failure is not a negative security finding.
- **PARTIAL COVERAGE != COMPLETED AUDIT** — completing some checks cannot satisfy a gate that requires checks which did not complete.
- **EXTERNAL SOURCE != TRUSTED FINDING** — imported material is untrusted until it passes the approved review and signing lifecycle.
- **FAILED OR STALE SOURCE != EMPTY SOURCE** — source failure or expired intelligence cannot be interpreted as a legitimate zero-advisory result.
- **GREEN TEST COUNT != PRESERVED TEST COVERAGE** — totals do not prove that earlier assertions or scenarios survived reorganization.
- **UNKNOWN COVERAGE != PASS** — a mandatory check with unknown coverage blocks PASS.

The general state-model doctrine is:

> ONE COVERAGE STATE + STRUCTURED REASON + SEPARATE DOMAIN LIFECYCLES

Each state dimension answers one question. A coverage enum states whether required evaluation occurred. Structured reasons explain why it did not. Source ingestion and advisory review lifecycles remain separate from audit coverage. Duplicate states such as `snapshot_status = STALE` and `advisory_coverage = STALE` are prohibited because they can diverge without adding information.

**CANONICAL — scan coverage model.** Scan coverage is modeled as `COMPLETED` or `INCOMPLETE`, with structured reasons including `HTTP_STATUS`, `TRANSPORT_ERROR`, `EXTRACTOR_ERROR`, `CHECK_NOT_TESTED`, `BUDGET_EXHAUSTED` and `REDIRECT_LOOP` (see §5). A `REDIRECT_LOOP` is a structured incomplete reason, not a policy status; it never becomes a trusted finding on its own.

**CANONICAL — policy result is tri-state.** Policy evaluation yields `PASS`, `FAIL` or `UNKNOWN`. Coverage and policy are separate contracts (§5.2), and unknown or failed coverage cannot be resolved to `PASS`.

## 3. Evidence review method

Critical review decisions use four distinct records:

| Stage | Required content |
| --- | --- |
| `CLAIM` | What a tool, agent or contributor says happened. |
| `EVIDENCE` | Raw or reproducible commands, artifacts, identities and results supporting the claim. |
| `REVIEW` | Independent interpretation, limitations and conflicts found in that evidence. |
| `DECISION` | `PASS`, `FAIL`, `BLOCKED` or `NEEDS_EVIDENCE`. |

A self-reported PASS is not sufficient evidence. A passing total is not sufficient evidence. For every critical claim, a reviewer must be able to reproduce or inspect the relevant command, commit, diff, fixture, assertion, digest or contract. Evidence scope must be stated; local evidence cannot be presented as remote CI evidence, and synthetic validation cannot be presented as real-client validation.

## 4. Test coverage preservation

Any commit that deletes, renames, moves, merges, parametrizes or reorganizes existing tests must include a coverage inventory:

```text
REMOVED_TESTS =
RENAMED_TESTS =
MERGED_TESTS =
PARAMETRIZED_TESTS =
NEW_TESTS =

OLD_TEST =
NEW_TEST =
ASSERTIONS_PRESERVED = YES/NO
REASON =
```

The inventory must list every affected test. When multiple old tests map to one new test, the reviewer must compare each old assertion independently. A renamed or parametrized test is preserved only when its security scenario and material assertions remain equivalent.

A green test count is never proof of preservation. Test reorganization can remove security coverage while the suite remains green because unrelated new cases keep the total stable or increase it. Clean-base regression proof must identify the base implementation, the source of overlaid tests, every overlaid or generated artifact and whether feature application code was present.

## 5. Scan completeness and CLI compatibility

**CANONICAL** — a mandatory observation that did not complete successfully cannot contribute to PASS. This invariant is implemented on `main`.

Scan/runtime status and policy status are separate contracts:

- runtime completeness describes whether required collection completed;
- policy evaluation describes whether evaluated evidence satisfies a policy;
- CLI exit codes expose the command result to automation.

### 5.1 Scan coverage state and structured reasons

**CANONICAL** — `AuditResult.scan_completeness` is `COMPLETED` or `INCOMPLETE`. An incomplete audit carries one or more required structured `ScanIssue` records. Reason kinds:

- `HTTP_STATUS` — a non-success HTTP response (carries a status code; other kinds must not).
- `TRANSPORT_ERROR` — transport failure prevented observation.
- `EXTRACTOR_ERROR` — an extractor failed on otherwise received content.
- `CHECK_NOT_TESTED` — a mandatory check was not exercised (carries a `check_id`).
- `BUDGET_EXHAUSTED` — the request budget was reached before a required observation completed.
- `REDIRECT_LOOP` — a redirect cycle was detected while resolving a resource.

Model constraints enforce consistency: `COMPLETED` requires no required issues, and `INCOMPLETE` requires at least one required issue.

### 5.2 Policy result tri-state

**CANONICAL** — `PolicyEvaluation.decision` is `PASS`, `FAIL` or `UNKNOWN`. When scan coverage is not `COMPLETED`, the decision is `UNKNOWN`; required failed or missing evidence cannot become `PASS`. When coverage is `COMPLETED`, the decision is `FAIL` if policy violations are present, otherwise `PASS`. A missing or failed mandatory observation is therefore never silently treated as a safe result.

### 5.3 Redirect / URL outcome versus scan coverage

**CANONICAL** — a URL outcome (for example a 301/302/404 response, a redirect destination or a detected redirect loop) is not the same as whole-scan completeness. Redirect handling may resolve to a scheduled same-origin resource, a recorded `REDIRECT_LOOP` incomplete reason, or a completed observation. None of these outcomes by itself asserts or denies overall scan completeness; that is determined solely by whether all required observations completed.

### 5.4 Retry rules

**CANONICAL** — retry and budget behavior is required-aware. A URL observation made while a target was optional is not equivalent to required coverage:

- a failed observation recorded while a target was optional does **not** satisfy that same target if it later becomes required;
- when the same target later becomes required, the scanner attempts it again; a prior optional failure cannot be counted as completed required coverage;
- optional resources that fail do not, by themselves, make the audit incomplete; required resources that fail record a required `ScanIssue`;
- when the request budget is reached before a required resource is attempted, the required resource is retained/re-queued and the scan ends `INCOMPLETE` with a `BUDGET_EXHAUSTED` reason rather than dropping the requirement;
- if a required retry cannot be executed because the request budget is exhausted, the scan remains `INCOMPLETE` with structured reason `BUDGET_EXHAUSTED`;
- retries remain bounded by the configured `max_requests` budget; no unbounded retry is permitted.

### 5.5 Legacy persisted audit handling

**CANONICAL** — legacy persisted audit records that lack sufficient current completeness evidence fail closed. A record with no `scan_completeness`/`scan_issues` pair is reconstructed as `INCOMPLETE` with a required `CHECK_NOT_TESTED` reason (`coverage:legacy-record`). A record carrying only one of the two fields is rejected. Legacy records therefore cannot be promoted to `COMPLETED` by omission.

### 5.6 CLI semantics

**CANONICAL** — runtime/incomplete execution semantics remain distinct from policy evaluation result semantics. Documented exit codes include:

```text
EXIT_OK = 0
EXIT_INVALID_INPUT = 2
EXIT_NOT_FOUND = 3
EXIT_INVALID_ADVISORY = 4
EXIT_RUNTIME_ERROR = 5
EXIT_POLICY_FINDINGS = 10
EXIT_MEANINGFUL_CHANGE = 11
EXIT_DOCTOR_FAILED = 12
```

An incomplete scan returns the runtime-error exit (`5`); policy findings return `10`. Changing an erroneous exit `0` to the documented runtime-error exit is an intentional security fix and an observable, backward-incompatible behavior change for automation that relied on the erroneous value. Review must report the before/after exit matrix, the documented contract, exact-code consumers and migration risk.

### 5.7 Schema and version contracts

**CANONICAL** — the current contracts expose:

```text
PolicyEvaluation  schema_version = 1.1
MonitorResult     schema_version = 1.1
MultistoreAudit   schema_version = 1.0
ScanPlan          format_version = 1.0
```

`ScanPlan` remains on `format_version` `1.0`: `required_requests` and `optional_requests` were additive properties accepted under the current export/versioning contract, and that specific additive evolution did not require a format bump. This is not a general guarantee: future additive properties must still be reviewed against the export contract and its semantic-compatibility rules before acceptance, and removal, rename or semantic reinterpretation of a field may require a version change. `PolicyEvaluation` and `MonitorResult` moved to `1.1` because their decision/state semantics changed. This record does not invent version increments.

### 5.8 Monitoring

**CANONICAL** — monitoring is baseline-aware and completeness-aware:

- a scan that is not `COMPLETED` cannot become a monitoring baseline; `MonitorResult.state` includes an `INCOMPLETE` state that carries the scan's `scan_completeness` and issues and never asserts change against a prior baseline;
- the previous-audit / baseline selector rejects unsuitable or incomplete state by requiring the candidate previous audit to be a non-demo record whose `scan_completeness` is `COMPLETED`;
- schema-invalid historical rows must not break previous-audit selection: rows that fail validation are skipped and the selector continues to the next candidate rather than failing.

### 5.9 Multistore

**CANONICAL** — multistore behavior preserves partial and exceptional evidence and stops at the first unsuccessful shop. Two distinct cases must not be conflated.

**Case A — a shop returns an `AuditResult` whose scan is `INCOMPLETE`:**

- evidence from shops already attempted/completed is retained;
- the incomplete shop result itself is retained with its structured scan issues;
- later shops are not treated as successfully completed and are not scanned;
- the multistore result remains incomplete, and incomplete/runtime failure semantics outrank a previously confirmed finding for CLI exit behavior: the command returns the runtime-error exit `5`, not the policy exit `10`;
- a fully completed batch with a confirmed finding still returns `10`.

**Case B — the scanner raises before producing an `AuditResult`:**

- previously completed shop evidence is preserved and persisted rather than discarded;
- the failed shop has no fabricated `AuditResult`;
- `MultistoreScannerError` carries the failed shop identity and the partial progress retained so far;
- runtime/incomplete semantics remain fail-closed, and the command returns the runtime-error exit `5`.

Only the runtime-error family (`OSError`, `httpx.HTTPError`) is wrapped for partial preservation. Not all exceptions are wrapped: validation and policy errors keep their non-runtime handling.

## 6. Current and proposed advisory trust boundary

**CANONICAL** — Current external payloads enter only through a local pending proposal. Manual promotion, schema validation, manifest regeneration and Ed25519 verification separate proposed material from the trusted advisory snapshot. The scanner consumes the reviewed snapshot, not raw external payloads.

**PROPOSED — Reviewed External Advisory Ingestion Pipeline**:

```text
External advisory sources
        ↓
Fetch / Import
        ↓
Normalize
        ↓
Schema validation
        ↓
Deduplicate / correlate
        ↓
PENDING REVIEW
        ↓
Deterministic and human review
        ↓
APPROVED
        ↓
Signed snapshot
        ↓
Advisory correlation engine
        ↓
Audit findings
```

External data never becomes trusted audit truth directly. Fetching, normalization or successful schema validation does not authorize promotion. The auditor consumes only reviewed and approved signed snapshots.

## 7. Proposed advisory domain model

The following domains are separate and must not be collapsed into one status enum.

### A. Advisory lifecycle

**PROPOSED**:

- `PENDING`: imported or authored record awaiting controlled review.
- `APPROVED`: accepted for an approved signed snapshot.
- `REJECTED`: reviewed and not accepted as current intelligence.
- `SUPERSEDED`: replaced by a newer or corrected advisory record.
- `REVOKED`: previously approved record that must no longer be treated as valid current intelligence.

Historical audit artifacts are immutable. Supersession or revocation must not silently rewrite a prior report. Current evaluation instead produces `REASSESSMENT_REQUIRED` or a new evaluation against a newer snapshot. The exact reassessment contract is an **OPEN DECISION**.

### B. Ingestion execution

**PROPOSED**:

- `SUCCESS`: the defined synchronization/import execution completed.
- `PARTIAL`: only part of the defined source set completed.
- `FAILED`: the execution did not produce its required synchronization result.

This domain describes one source operation. It is not scan completeness and does not directly decide audit coverage.

### C. Audit advisory coverage

**PROPOSED**:

- `COMPLETE`: required advisory-dependent evaluation used an acceptable approved snapshot.
- `INCOMPLETE`: evaluation started or had prior intelligence but mandatory coverage requirements were not satisfied.
- `NOT_TESTED`: no usable evaluation was performed for the required advisory capability.

The coverage cause is stored separately as a structured reason. Ingestion execution may be `FAILED` while coverage remains `COMPLETE` when a previously approved snapshot is still acceptable under the configured freshness policy.

## 8. Proposed structured coverage reasons

Candidate reason codes are:

- `STALE_SNAPSHOT`
- `SNAPSHOT_MISSING`
- `SIGNATURE_INVALID`
- `SOURCE_FETCH_FAILED`
- `SOURCE_PARSE_FAILED`
- `SOURCE_SCHEMA_INVALID`
- `SOURCE_CONFLICT`
- `REVIEW_PENDING`
- `REVIEW_BACKLOG_EXCEEDED`
- `UNSUPPORTED_SOURCE`
- `INTERNAL_ERROR`

`REVOKED` and `SUPERSEDED` remain lifecycle states. If either prevents current evaluation from using a snapshot, the coverage layer records a structured reason and reassessment requirement without duplicating the lifecycle enum. Exact reason-to-lifecycle mapping remains part of the discovery/schema gate.

## 9. Proposed freshness contract

Every advisory-dependent evaluation should expose at least:

- `snapshot_id`
- `created_at`
- `signed_at`
- `source_set_digest`
- `last_successful_sync_at`
- `evaluated_at`
- `age_seconds`

The acceptable freshness threshold is an explicit configuration or policy decision. It must not be an undocumented constant. A stale snapshot cannot silently produce PASS for a mandatory advisory-dependent check.

Freshness and ingestion execution remain independent. If the last successful sync was three hours ago, the threshold is 24 hours and the latest attempt failed, ingestion execution may be `FAILED` while audit advisory coverage remains `COMPLETE`. Once the accepted threshold is exceeded without a successful refresh, coverage becomes `INCOMPLETE` with reason `STALE_SNAPSHOT`.

The threshold, clock source, grace behavior and per-source versus snapshot-wide evaluation are **OPEN DECISIONS**.

## 10. Proposed source failure mapping

| Situation | Coverage | Structured reason | Advisory-dependent PASS allowed |
| --- | --- | --- | --- |
| Valid signed snapshot and required sources current | `COMPLETE` | none | YES |
| Snapshot exceeds freshness threshold | `INCOMPLETE` | `STALE_SNAPSHOT` | NO |
| No usable snapshot | `NOT_TESTED` | `SNAPSHOT_MISSING` | NO |
| Snapshot signature invalid | `NOT_TESTED` | `SIGNATURE_INVALID` | NO |
| Required source fetch fails and no acceptable current snapshot exists | `INCOMPLETE` | `SOURCE_FETCH_FAILED` | NO |
| Required source cannot be parsed | `INCOMPLETE` | `SOURCE_PARSE_FAILED` | NO |
| Required source schema is invalid | `INCOMPLETE` | `SOURCE_SCHEMA_INVALID` | NO |
| Required sources conflict materially | `INCOMPLETE` | `SOURCE_CONFLICT` | NO |
| Source correctly returns zero advisories | `COMPLETE` | none | policy-dependent |
| Required advisory awaits review | `INCOMPLETE` or excluded from approved snapshot | `REVIEW_PENDING` | NO trusted finding |
| Required source or capability is unsupported | `NOT_TESTED` | `UNSUPPORTED_SOURCE` | NO when mandatory |

The governing invariant is:

> SOURCE FAILURE != ZERO ADVISORIES

This table is **PROPOSED** and must be frozen with deterministic fixtures during the advisory discovery/schema gate.

## 11. Proposed review queue health

Operational observability should expose:

- `pending_total`
- `oldest_pending_age`
- `new_records_24h`
- `approved_24h`
- `rejected_24h`
- `conflicted_total`
- `stale_sources`
- `last_successful_sync`
- `review_throughput`

A running or successful ingestion job is not proof that current advisory coverage is acceptable. Queue health and snapshot coverage are separate observations. Automation may fetch, parse, normalize, deduplicate, detect conflicts and prioritize records. It must not approve records automatically merely to reduce backlog. Transition into trusted state remains controlled.

Review ownership, service level, backlog thresholds and whether backlog age changes coverage are **OPEN DECISIONS**.

## 12. Proposed provenance model

An imported advisory record should preserve at least the following candidate fields:

- source identity: `source_id`, source URL or reference, `source_advisory_id`;
- source time: `source_published_at`, `source_updated_at`, `fetched_at`;
- content identity: `raw_payload_digest`, `normalized_record_digest`;
- affected intelligence: affected range and fixed version where available;
- review: `review_state`, `reviewed_at`, reviewer identifier;
- snapshot relation: `source_set_digest`;
- history: `supersedes`, `superseded_by`, and revocation reference where applicable.

This list is **PROPOSED**, not a frozen schema. Field names, requiredness, privacy constraints and migration rules must be reviewed in the dedicated discovery/schema gate. Current canonical advisory schema and provenance rules remain unchanged.

## 13. Roadmap and gate sequence

### Current gate

**CLOSED — CANONICAL.** The scan-completeness and false-PASS hardening gate closed on `main` via `ffd8542c15a4f1dc34a5a2fb650471cf6d23829a` (pull request #6) and `be94954a4f27463e094cd30e5561f0c094e7c6a9` (pull request #7). The behavior described in §5 is canonical. No further candidate reconciliation is required for this workstream.

### Post-merge roadmap

The following sequence is **FUTURE** and each workstream requires an isolated decision and validation gate:

1. centralized privacy, persistence and export boundary;
2. reviewed external advisory ingestion, beginning with discovery/schema/trust review;
3. PHP and database environment evidence contract and fingerprinting;
4. Composer vulnerability correlation;
5. filesystem and PHP hardening profile;
6. secret-scanning evaluation;
7. SAST evaluation;
8. malware and webshell evaluation;
9. TLS, database privilege and PrestaShop 9 scope checks;
10. full synthetic validation;
11. controlled real-client pilot readiness.

No real-client pilot is authorized until every required validation and governance gate is explicitly closed.

## 14. First advisory-ingestion gate

The first work item is **PROPOSED DISCOVERY + SCHEMA + TRUST MODEL**, not implementation. It must decide and review:

- approved source types and authority ranking;
- normalization schema and provenance requirements;
- version-range normalization;
- deduplication and cross-source conflict handling;
- freshness policy and failure-to-state mapping;
- review lifecycle, revocation, supersession and reassessment behavior;
- queue ownership, review service level and queue-health thresholds;
- signing lifecycle and snapshot versioning;
- deterministic fixtures and offline reproducibility;
- rollback and recovery behavior.

No ingestion implementation starts before these decisions are reviewed and the resulting contracts are versioned.

## 15. Open decision register

The following are **OPEN DECISIONS**:

| ID | Decision required | Gate that owns closure |
| --- | --- | --- |
| `ADV-OPEN-001` | Exact freshness thresholds and grace behavior | Advisory discovery/schema gate |
| `ADV-OPEN-002` | Mandatory versus optional sources | Advisory discovery/schema gate |
| `ADV-OPEN-003` | Reviewer ownership and separation of duties | Trust/governance review |
| `ADV-OPEN-004` | Review service level and queue-health thresholds | Trust/governance review |
| `ADV-OPEN-005` | Source authority ranking | Advisory discovery/schema gate |
| `ADV-OPEN-006` | Adjudication of contradictory sources | Advisory discovery/schema gate |
| `ADV-OPEN-007` | Whether backlog age automatically degrades coverage | Freshness/coverage review |
| `ADV-OPEN-008` | Exact advisory and ingestion schemas | Schema version gate |
| `ADV-OPEN-009` | Snapshot retention and rollback policy | Release/operations review |
| `ADV-OPEN-010` | Reassessment trigger and output contract | Evaluation-contract review |
| `ADV-OPEN-011` | Relation between revoked advisories and issued reports | Governance/evaluation review |
| `ADV-OPEN-012` | Per-source versus whole-snapshot freshness | Freshness/coverage review |

Open items must not be resolved implicitly in code. Closing an item requires a recorded claim, reproducible evidence, independent review and explicit decision.

## 16. Change control

This record is accepted only through independent review. A status transition from `PROPOSED` to `CANONICAL` requires evidence that the corresponding implementation and contracts are present on `main`. Historical statements remain dated; they are not rewritten to imply earlier availability.

Changes to status semantics, trust boundaries, failure mappings or evidence requirements require focused fixtures and compatibility review. Advisory-data changes should remain reviewable independently from scanner behavior. No real-client evidence, domain, credential, cookie, token, secret or private infrastructure information belongs in this document or the public repository.
