# Validation corpus protocol

Status: synthetic rehearsal schema v1 implemented; no client-data collection is authorized by this document.

This protocol defines how LOGIALOG PrestaShop Security Auditor may later be evaluated on a consented, minimized and reproducible corpus. Its purpose is to show where the tool is correct, where it fails and where it remains indeterminate. It is not designed to prove compromise, certify a shop as secure or manufacture stronger product claims.

The product-claim boundary remains defined in [areas/POSITIONING_ARGUMENTS.md](areas/POSITIONING_ARGUMENTS.md).

## 1. Research questions

The corpus may answer only these questions:

1. How accurately does each remote extractor identify a component and version relative to trusted local or authenticated evidence?
2. How often does advisory correlation correctly classify a known component version relative to independently reviewed advisory evidence?
3. Do qualitative evidence tiers produce an ordinal error pattern, where stronger evidence is less error-prone than weaker evidence?
4. Under which PrestaShop, hosting, CDN/WAF and asset conditions does the tool return incorrect or indeterminate results?
5. What bounded operational effects are observed during authorized scans?

It must not report “compromise detected”, estimate breach prevalence or infer the security of the whole shop.

## 2. Unit of evaluation

The primary unit is one extractor observation for one component in one explicitly authorized shop snapshot. A shop may contribute multiple observations, but shop-level clustering must be preserved during analysis; observations from the same shop are not statistically independent.

Every observation receives a random corpus identifier. Customer names, production domains and internal project identifiers are excluded from the analysis dataset.

## 3. Two independent ground truths

Fingerprint accuracy and advisory correctness are separate questions and must never share one “vulnerability detected” label.

### A. Fingerprint ground truth

Purpose: determine the exact installed component and version at the time of the remote observation.

Accepted evidence, strongest first:

1. SHA-256-hashed local module metadata or PrestaShop version metadata collected from the same deployment snapshot.
2. Authenticated Back Office version evidence captured by an authorized reviewer at the same time.
3. A deployment manifest tied to the same immutable release or artifact digest.

Public fingerprints, CDN assets and the tool's own output cannot establish their own ground truth. Conflicting evidence is labelled `GROUND_TRUTH_CONFLICT` and excluded from correctness metrics while remaining visible in the flow diagram.

### B. Advisory ground truth

Purpose: determine whether the exact ground-truth version falls inside an affected range from an independently reviewed advisory.

Requirements:

1. The advisory identity, source authority, publication date, affected range and fixed version are reviewed independently of the scanner output.
2. The reviewer records all material source conflicts according to [ADVISORY_REVIEW.md](ADVISORY_REVIEW.md).
3. Missing or conflicting version boundaries produce `ADVISORY_UNKNOWN`, not an affected or fixed label.
4. The advisory reviewer must not use the scanner's classification as evidence.

This ground truth validates version-to-advisory correlation only. It never establishes exploitation or compromise.

## 4. Sampling and stratification

A volunteer or convenience corpus is not representative of the PrestaShop ecosystem. Results from such a corpus must be described only as “performance on the validation corpus”.

Sampling targets are defined before collection across these strata:

| Dimension | Planned strata |
| --- | --- |
| PrestaShop core | Each supported major/minor family represented in the pilot |
| Hosting | Shared, VPS/dedicated, managed PrestaShop, containerized |
| Edge layer | No CDN/WAF, CDN only, WAF only, CDN and WAF |
| Module provenance | Official/vendor, community, custom/private |
| Version exposure | Exact, partial, absent, conflicting/spoofed |
| Asset condition | Current, stale cache, renamed, minified/bundled, removed |
| Ground-truth state | Available, unavailable, conflicting |

Recruitment source and selection mechanism are recorded for every shop. No ecosystem-wide inference is permitted until the sampling frame, non-response and coverage limitations are defensible.

The pilot must publish the achieved stratum counts; it must not hide sparse or empty cells by merging them after results are known.

## 5. Consent and authorization

Collection requires a separate, recorded authorization for each shop. Dashboard checkboxes and CLI flags are self-attestation controls, not proof of ownership.

Before collection, the owner-approved consent record must define:

- exact origin and public pages in scope;
- scan date window, request budget and delay;
- purpose of the validation study;
- categories of data collected and explicitly excluded;
- who may access raw evidence;
- retention and destruction dates;
- whether anonymized aggregate results may be published;
- withdrawal procedure and the limits of withdrawal after aggregate publication;
- incident and stop contacts.

Silence, an existing support contract or public accessibility is not consent. A shop is excluded when authority is ambiguous.

## 6. Data minimization and privacy

The analysis dataset may contain:

- random corpus, shop and observation identifiers;
- declared strata;
- extractor/rule version;
- normalized component name and ground-truth version;
- qualitative confidence tier and detection method;
- fingerprint and advisory outcome labels;
- hashes of approved evidence files or responses;
- bounded request count and operational-event categories;
- reviewer IDs or pseudonyms needed for auditability.

It must not contain:

- production domains, IP addresses or customer names;
- credentials, session identifiers, cookies, tokens or secrets;
- personal data, order/customer data or full databases;
- raw access logs beyond an explicitly approved minimized extract;
- full source files, proprietary module code or unredacted HTTP bodies;
- exploit payloads or compromise claims.

Raw evidence and the analysis dataset remain separate. Publication uses aggregate tables with disclosure review and minimum-cell suppression defined before analysis.

## 7. Dataset record specification

Each observation record requires the following logical fields before the pilot schema is implemented:

| Group | Required fields |
| --- | --- |
| Identity | corpus schema version, random shop ID, observation ID, collection timestamp |
| Scope | normalized origin category, authorized page category, request budget, requests sent |
| Strata | core family, hosting, edge layer, module provenance, exposure, asset condition |
| Detector | extractor ID/version, detection method, qualitative confidence tier, observed component/version |
| Fingerprint truth | truth source type, evidence SHA-256, component/version, truth status, reviewer |
| Fingerprint outcome | `TP`, `FP`, `FN`, `CORRECT_ABSTENTION`, `INDETERMINATE`, `GROUND_TRUTH_CONFLICT` |
| Advisory truth | advisory record/version, source set, review status, affected/fixed/unknown classification |
| Correlation outcome | `CORRECT`, `INCORRECT`, `UNKNOWN`, `NOT_APPLICABLE` |
| Operations | WAF/rate-limit/SOC/logging/instability observations, stop event, incident reference |

Absolute filesystem paths and raw evidence content are not analysis fields.

### Synthetic implementation

The current synthetic-only implementation consists of:

- [validation-corpus-v1.schema.json](validation-corpus-v1.schema.json): versioned JSON Schema generated from the strict Pydantic validation model;
- [backend/app/validation_corpus.py](../backend/app/validation_corpus.py): offline loader, outcome-coherence rules and recursive privacy rejection;
- [tests/fixtures/validation-corpus.synthetic.json](../tests/fixtures/validation-corpus.synthetic.json): six obviously synthetic observations covering every fingerprint outcome, every advisory-correlation outcome and all qualitative confidence tiers;
- [tests/fixtures/validation-corpus.invalid-privacy.json](../tests/fixtures/validation-corpus.invalid-privacy.json): reserved and synthetic negative cases for forbidden fields, URI/domain-like values, email-like values, IPv4/IPv6 addresses, credentials, UNC paths and plausible absolute production paths;
- [tests/test_validation_corpus.py](../tests/test_validation_corpus.py): schema-drift, malformed-record, privacy, enum-domain and synthetic-validation-path no-network regression tests.

The synthetic timestamps use the year 2000, every identifier is prefixed with `synthetic-`, and every record declares zero requests sent. These fixtures are structural validation data, not product-performance evidence.

`validation-corpus-v1` is frozen only as synthetic rehearsal schema v1. It is not automatically the schema for a future real-client corpus. Any future consented corpus requires a separately versioned schema and an explicit review gate covering consent, minimization, access control, retention and collection behavior before use.

The preparation templates, frozen rehearsal inputs, metric rules and lifecycle procedures are consolidated in [VALIDATION_GOVERNANCE.md](VALIDATION_GOVERNANCE.md). Its machine-readable rehearsal remains non-operational: owner assignments are synthetic, approval is pending, and real recruitment, evidence, domains, production access and collection authorization are fixed to `false`.

## 8. Evaluation metrics

### Fingerprint metrics

Report counts and rates per extractor and predeclared stratum:

- true positives, false positives and false negatives;
- correct abstentions and indeterminate outcomes;
- precision and recall only where their denominators and ground truth are valid;
- indeterminate rate and ground-truth availability/conflict rate;
- shop-clustered confidence intervals when the sample size supports them.

Do not silently remove indeterminate observations. Publish the complete flow from recruited shops to metric-eligible observations.

### Advisory-correlation metrics

Report `CORRECT`, `INCORRECT`, `UNKNOWN` and `NOT_APPLICABLE` counts separately. Do not call these vulnerability-detection TP/FP/FN metrics and do not combine them with fingerprint errors.

### Qualitative confidence tiers

The initial table is descriptive:

| Tier | N | Correct | Incorrect | Indeterminate | Error rate among decidable observations |
| --- | ---: | ---: | ---: | ---: | ---: |
| High |  |  |  |  |  |
| Medium |  |  |  |  |  |
| Low |  |  |  |  |  |

The phase-one hypothesis is ordinal: `error_rate(HIGH) < error_rate(MEDIUM) < error_rate(LOW)`. Failure of this ordering must be reported and may require changing evidence-tier definitions.

No reliability diagram, calibration curve, Brier score or probability language is permitted unless a future version introduces a numeric score with an explicitly probabilistic meaning and a separately approved analysis plan.

## 9. Review independence and quality control

- Collection, fingerprint ground-truth review and advisory review are recorded as separate roles. One person may fill multiple roles in a small pilot, but the overlap must be disclosed.
- Reviewers use a frozen code commit, extractor version, advisory snapshot and dataset schema.
- A second reviewer adjudicates conflicts and a predeclared sample of ordinary records.
- Corrections are append-only: the original label, new label, reason, reviewer and timestamp remain auditable.
- Test fixtures remain synthetic; client observations are never committed to the public repository.

## 10. Retention and destruction

Before collection, the owner sets separate retention periods for consent records, raw evidence, review artifacts and the anonymized analysis dataset.

At the destruction date:

1. delete raw evidence and reversible lookup tables from approved storage;
2. record the deletion scope, date and responsible reviewer;
3. retain only the fields allowed by consent and publication policy;
4. propagate deletion to backups according to the documented backup lifecycle;
5. confirm that no corpus material entered Git history, CI artifacts or public issues.

Withdrawal and legal-hold handling must be documented before the pilot starts.

## 11. Pilot gates

Client-data collection remains blocked until all items are approved:

- [x] named data controller and research owner, using a public research-owner ID with the personal mapping retained privately;
- [ ] consent text and authorization record;
- [x] machine-readable schema with forbidden-field validation, exercised with synthetic fixtures only;
- [ ] fingerprint ground-truth review form;
- [ ] advisory ground-truth review form;
- [ ] stratified sampling targets and recruitment record;
- [ ] frozen extractor/advisory versions;
- [ ] metric calculation and exclusion rules;
- [ ] access-control, retention, deletion and incident procedures;
- [x] synthetic end-to-end rehearsal using no PII or real domain; the synthetic corpus validation path is tested to perform no network access.

Unchecked gates are intentional owner/research prerequisites, not permission to collect opportunistic samples.

Implementation readiness is separate from owner approval. The repository now contains synthetic templates for consent, fingerprint review, advisory review, sampling/recruitment, technical freeze, metrics, lifecycle and incident handling. Their presence does not check the approval gates above or authorize real-client activity.

## 12. Publication language

Allowed before representative sampling:

> On the consented validation corpus, extractor X produced the reported outcomes under the published protocol and stratum distribution.

Prohibited without further evidence:

> The tool achieves this performance across the PrestaShop ecosystem.

Every result must publish the protocol version, frozen commit, advisory snapshot, achieved strata, missing ground truth, exclusions, uncertainty and known sources of bias.

## 13. Change control

The protocol receives a version before the pilot. Hypotheses, labels, exclusions and primary metrics are frozen before viewing results. Any later change is logged with rationale and classified as prospective or exploratory; it must not be presented as if it had been predeclared.

The claim rule remains:

> CLAIM → CODE / TEST / DOCUMENTATION / DATASET / NAMED EXTERNAL SOURCE; otherwise HYPOTHESIS.
