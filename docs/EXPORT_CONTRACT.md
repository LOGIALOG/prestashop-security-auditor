# Export compatibility contract

## LOGIALOG JSON

Current `format_version`: `1.0`.

Top-level fields are `format`, `format_version`, `demo` and `audit`. The audit payload follows the API model, except that local filesystem paths are excluded. Consumers must reject unsupported major versions and may accept new fields within the same major version.

The audit payload exposes `scan_completeness` as `COMPLETED` or `INCOMPLETE` and records bounded `scan_issues`. Each issue identifies whether the failed resource or check was required. Optional `detail` and `captured_at` fields may accompany an issue with bounded, redacted failure context; they are additive, carry no decision authority, and do not change coverage semantics. HTTP failures on discovered optional assets remain visible without making mandatory coverage incomplete; failures on the root, explicitly requested public pages, required extractors or required checks make the audit incomplete. Consumers must not convert an incomplete audit into a successful policy decision, even when its findings list is empty.

Evidence provenance fields (`url`, `captured_at`, `evidence_type`, `excerpt`, `response_sha256`, `confidence` and `detection_method`) will not be removed or change meaning within version 1.

## SARIF

The SARIF export targets SARIF `2.1.0`. Finding subjects map to rules, findings map to results and captured evidence maps to locations with provenance properties. Demo state, scan completeness and structured scan issues are present at run level; demo state is also present at result level.

`ASSET_RESIDUE` and `NOT_AFFECTED` are emitted as notes. Their presence must not be interpreted as a confirmed vulnerability.

## Compatibility changes

- Additive optional properties: compatible change.
- Removing or renaming fields, changing evidence semantics or changing status meanings: major format change.
- Export changes require fixture-based compatibility tests before release.

## CycloneDX

Local source inventory exports CycloneDX `1.6`. Component versions come only from local metadata; missing versions remain absent. Composer packages receive `pkg:composer` package URLs. The BOM serial number is deterministic for an identical ordered component inventory, and the export states the LOGIALOG tool version in CycloneDX metadata.

Local assessment CycloneDX exports add vulnerability objects linked to stable component `bom-ref` values. `analysis.state` distinguishes `in_triage` from `not_affected`; evidence paths, SHA-256 hashes and advisory provenance remain properties of each assertion.

## Local assessment and preflight formats

`logialog-local-source-assessment`, `logialog-doctor` and `logialog-scan-plan` currently use `format_version` `1.0`. Their safety fields (`network_access`, code-execution flags and cross-origin behavior) are assertions with stable meaning. Removing evidence provenance, weakening a safety assertion or changing a state meaning requires a new major format version.

`logialog-scan-plan` `1.0` additively exposes `required_requests` and `optional_requests` alongside `fixed_requests`; this is a compatible within-major addition under the additive-property rule above and does not require a version bump. Adding further optional properties keeps `1.0`; removing a listed field, changing its meaning or weakening a safety assertion requires a new major version and fixture-based compatibility tests.

Local assessment SARIF targets SARIF `2.1.0` and points each result to the local metadata file used as version evidence. An affected version correlation is a remediation signal, not exploitation evidence.
