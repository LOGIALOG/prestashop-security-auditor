# Policy packs

Policy packs are versioned JSON release gates. They evaluate existing facts and never change a finding, status, score or evidence record.

Two generic packs are included:

- `policies/agency-release.json`: refuses confirmed or likely findings, requires a minimum score of 70, medium-or-better evidence and a report hash.
- `policies/triage.json`: permits bounded findings for early investigation while still requiring a report hash.

Both reject demo data by default.

## Schema 1.0

- `policy_id` and `title`: stable identity and readable name.
- `allow_demo`: whether clearly marked demo data can pass.
- `minimum_score`: optional score floor from 0 to 100.
- `fail_on_statuses`: statuses that cause failure when present.
- `maximum_counts`: optional per-status limits.
- `minimum_evidence_confidence`: `low`, `medium` or `high`.
- `require_report_hash`: require the canonical report SHA-256.

Unknown fields, invalid statuses, duplicate forbidden statuses and invalid limits are rejected.

## Evaluate

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli policy evaluate AUDIT_ID `
  --policy policies\agency-release.json `
  --output reports\policy-result.json
```

The result lists every violated rule and the related subjects. `PASS` returns exit code `0`; `FAIL` returns `10`, making the same policy usable locally and in CI. An audit whose `scan_completeness` is `INCOMPLETE` produces `UNKNOWN`, never `PASS`; the CLI treats every non-`PASS` policy result as a blocking exit.

Policy evaluation output uses schema `1.1`. This version adds the `UNKNOWN` decision so strict consumers can distinguish incomplete evidence from a completed policy failure. Policy pack input remains schema `1.0`.

Copy a bundled pack to `policy.local.json` for private thresholds. That filename is ignored by Git. Do not place client identity, domains or credentials in a policy pack.
