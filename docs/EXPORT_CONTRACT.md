# Export compatibility contract

## LOGIALOG JSON

Current `format_version`: `1.0`.

Top-level fields are `format`, `format_version`, `demo` and `audit`. The audit payload follows the API model, except that local filesystem paths are excluded. Consumers must reject unsupported major versions and may accept new fields within the same major version.

Evidence provenance fields (`url`, `captured_at`, `evidence_type`, `excerpt`, `response_sha256`, `confidence` and `detection_method`) will not be removed or change meaning within version 1.

## SARIF

The SARIF export targets SARIF `2.1.0`. Finding subjects map to rules, findings map to results and captured evidence maps to locations with provenance properties. Demo state is present at run and result level.

`ASSET_RESIDUE` and `NOT_AFFECTED` are emitted as notes. Their presence must not be interpreted as a confirmed vulnerability.

## Compatibility changes

- Additive optional properties: compatible change.
- Removing or renaming fields, changing evidence semantics or changing status meanings: major format change.
- Export changes require fixture-based compatibility tests before release.

## CycloneDX

Local source inventory exports CycloneDX `1.6`. Component versions come only from local metadata; missing versions remain absent. Composer packages receive `pkg:composer` package URLs. The BOM serial number is deterministic for an identical ordered component inventory, and the export states the LOGIALOG tool version in CycloneDX metadata.
