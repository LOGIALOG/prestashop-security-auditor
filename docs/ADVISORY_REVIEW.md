# Advisory review and promotion

Imported upstream data is untrusted. The `advisories propose` command accepts only a local JSON payload, normalizes it and writes a pending review document. It never writes to `advisories/` and performs no network request.

## Create a review candidate

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli advisories propose `
  --adapter friendsofpresta `
  --input upstream.json `
  --retrieved-at 2026-09-06 `
  --output review-queue\candidate.json
```

The reviewer must compare `source_payload_sha256` with the locally archived upstream payload and open the direct `source` URL independently.

## Conflict policy

1. CVE/NVD identifiers establish identity but do not override the affected ranges published by the maintainer or coordinated PrestaShop advisory.
2. A direct module-maintainer or PrestaShop Project statement has priority for fixed-version information when it clearly addresses the same issue.
3. Friends of Presta supplies PrestaShop-specific coordination context and may define a safer minimum version than a generic CVE record.
4. Conflicting affected or fixed ranges block promotion. Record both sources in the review discussion; never choose the more severe range automatically.
5. Missing authentication, version-boundary or source information blocks promotion.
6. Risk wording must describe possible impact conditionally and must not claim observed exploitation.

## Manual promotion

1. Review every checklist item in the pending document.
2. Copy only `proposed_record` into a correctly named file under `advisories/`.
3. Run `advisories validate` before changing the manifest; it is expected to report manifest drift.
4. Run `advisories manifest`, inspect the changed record hash and record count, then run `advisories validate` again.
5. Run the complete offline test suite.
6. Review advisory-data changes separately from scanner logic whenever practical.

Generated review candidates belong in `review-queue/` and are ignored by Git until explicitly curated into a trusted advisory record.
