# Validation governance pack

Status: synthetic rehearsal complete; real-client collection remains blocked pending named owners and explicit approvals.

This pack implements the preparation artifacts required by [VALIDATION_PROTOCOL.md](VALIDATION_PROTOCOL.md). It does not authorize collection, replace legal review or turn the synthetic rehearsal schema into a real-client schema.

The machine-readable rehearsal is [validation-governance.synthetic.json](../tests/fixtures/validation-governance.synthetic.json). All identifiers and dates in that file are synthetic, and every collection or real-evidence flag is fixed to `false`.

## 1. Owner assignment record

The owner must complete and approve this record before recruitment or collection:

| Field | Required decision |
| --- | --- |
| Data controller | Legal entity name, registered address and accountable representative; confirm applicable jurisdiction with counsel |
| Research owner | Named person accountable for protocol execution, deviations and publication |
| Security contact | Named recipient and approved contact channel for incidents and stop requests |
| Privacy contact | Named recipient and approved contact channel for access, withdrawal and deletion requests |
| Approval | Approver identity, UTC timestamp, protocol version and immutable approval-record digest |

The repository contains no personal names or contact details. Those records belong in approved private storage, never Git, CI artifacts or public issues.

## 2. Consent and authorization record

Create one independently approved record per shop. Consent is invalid unless every item below is explicit:

- authority of the signer and relationship to the shop owner;
- exact origin and public-page categories in scope, stored privately outside the analysis corpus;
- authorized UTC window, request budget, delay, same-origin rule and GET-only behavior;
- research purpose and the distinction between fingerprint and advisory-correlation outcomes;
- allowed data categories and explicit exclusions;
- people or roles allowed to access consent records, raw evidence, review artifacts and analysis data;
- retention and destruction dates for each storage class;
- publication choice for anonymized aggregate results;
- withdrawal procedure and limitations after aggregate publication;
- incident contact, stop contact and immediate-stop conditions;
- signer, reviewer and approval timestamps plus an immutable record digest.

Authorization must be verified by the named research owner. A dashboard checkbox, CLI flag, public accessibility, silence or an unrelated support contract is insufficient.

## 3. Fingerprint ground-truth review form

The private review record must contain:

| Field | Rule |
| --- | --- |
| Observation ID | Random or synthetic identifier only |
| Truth status | `AVAILABLE`, `UNAVAILABLE` or `CONFLICTING` |
| Source type | Local metadata, authenticated Back Office, deployment manifest or none |
| Component present | Boolean only when truth is available |
| Exact component/version | Required only when an available component is present |
| Evidence digest | SHA-256 of approved evidence; raw evidence remains separate |
| Reviewer | Approved reviewer identifier |
| Review time | UTC timestamp tied to the same deployment snapshot |
| Adjudication | Second-reviewer decision for conflicts or sampled quality control |

Public fingerprints and scanner output cannot establish their own ground truth. A conflict remains `GROUND_TRUTH_CONFLICT`; missing evidence remains `INDETERMINATE`.

## 4. Advisory ground-truth review form

The advisory reviewer works independently from fingerprint collection and records:

- observation and advisory identifiers;
- advisory schema/version and reviewed source-set digest;
- source authority, publication date, affected range and fixed version in private review evidence;
- source conflicts and their resolution or unresolved state;
- truth classification and scanner-observed classification as separate fields;
- `CORRECT`, `INCORRECT`, `UNKNOWN` or `NOT_APPLICABLE` correlation outcome;
- reviewer identifier, UTC review timestamp and second-review status.

Advisory correlation never establishes exploitation or compromise. Missing or conflicting boundaries remain `UNKNOWN`.

## 5. Sampling and recruitment plan

Before recruitment, the research owner must freeze numeric targets across all canonical dimensions:

- PrestaShop core family;
- hosting model;
- edge layer;
- module provenance;
- version exposure;
- asset condition;
- ground-truth availability.

The recruitment record stores a random candidate identifier, recruitment source, selection mechanism, eligibility state, non-response state and exclusion reason. Numeric targets, recruitment channels, stopping rules and minimum publishable cell size require owner approval before any invitation is sent.

A convenience or volunteer sample is reported only as performance on that validation corpus. Sparse cells, non-response and post-hoc exclusions remain visible.

## 6. Frozen technical inputs

The synthetic rehearsal pins these inputs in the machine-readable manifest:

| Input | Frozen value |
| --- | --- |
| Baseline `main` commit | `a01d7763e34b8ee231d2d583bee288bac24c0118` |
| Remote extractor source SHA-256 | `4d5b8b10bfb1ab17beb4650d935a55e43cd0f116771190daaef0413930d85637` |
| Advisory manifest SHA-256 | `f7c80b4f5422f5ada81bc31dd59e3f7d19a87a08400726a80624041417f38ff5` |
| Synthetic corpus schema SHA-256 | `86dd4b1ef50ec19883158b0fa3c6c59f4eceb010e5c7a959e9aa427ee57c9dc5` |

These hashes freeze only the synthetic rehearsal. A consented pilot requires a new reviewed freeze record tied to its separately versioned schema, code commit and advisory snapshot.

## 7. Metric and exclusion rules

Fingerprint and advisory domains remain separate:

- fingerprint counts: `TP`, `FP`, `FN`, `CORRECT_ABSTENTION`, `INDETERMINATE`, `GROUND_TRUTH_CONFLICT`;
- advisory counts: `CORRECT`, `INCORRECT`, `UNKNOWN`, `NOT_APPLICABLE`;
- `INDETERMINATE` and `GROUND_TRUTH_CONFLICT` remain visible but are excluded from correctness denominators;
- precision uses `TP / (TP + FP)` only when the denominator and ground truth are valid;
- recall uses `TP / (TP + FN)` only when the denominator and ground truth are valid;
- observations are analyzed with shop-level clustering; repeated observations are not independent;
- exclusions, missing truth, conflicts, non-response and achieved stratum counts are published;
- `HIGH`, `MEDIUM` and `LOW` are qualitative evidence tiers, never probabilities;
- no ecosystem-wide or compromise claim is allowed from the rehearsal or a convenience corpus.

Any metric not predeclared before viewing results is labelled exploratory.

## 8. Access, retention, deletion and incident procedure

The owner must approve a private data register with separate storage classes for consent, lookup keys, raw evidence, review artifacts and minimized analysis records.

For each class, record:

- approved roles and least-privilege access mechanism;
- storage location and encryption requirements;
- creation, retention and destruction dates;
- backup coverage and deletion-propagation deadline;
- access-review frequency and audit-log owner;
- withdrawal, legal-hold and incident handling.

Immediate-stop conditions include scope ambiguity, authorization withdrawal, unexpected personal or secret material, WAF/SOC escalation, service instability, request-budget breach or inability to maintain evidence separation.

On stop: cease collection, preserve only the minimum incident record, notify the approved contacts, quarantine affected material, record the decision and do not resume without renewed approval.

Raw evidence, consent records, lookup tables and personal contacts must never enter Git history, CI artifacts, public issues or the analysis dataset.

## 9. Gate state

Preparation completed in this repository:

- machine-readable synthetic governance rehearsal;
- consent and authorization template;
- fingerprint and advisory review templates;
- sampling and recruitment template;
- frozen synthetic technical inputs;
- metric and exclusion rules;
- lifecycle and incident procedure;
- automated validation and non-authorization tests.

Still requiring real owner action before any real-client activity:

1. name the data controller and research owner;
2. approve jurisdiction-appropriate consent text and private record storage;
3. approve numeric sampling targets and recruitment channels;
4. approve access roles, retention periods, deletion deadlines and incident contacts;
5. review and version a separate consented-corpus schema;
6. issue an explicit collection authorization tied to the final freeze record.

Until all six decisions are recorded, `collection_authorized` remains `false` and no real recruitment, domain handling, evidence collection or production access is permitted.
