# Advisory schema policy

Current schema version: `1`.

Every advisory is a standalone JSON document validated before it is used by the scanner. Unknown fields are rejected so spelling mistakes and unreviewed data cannot silently affect a finding.

## Required provenance

All records contain:

- `schema_version`: integer schema contract version.
- `record_id`: stable, globally unique identifier inside the snapshot.
- `source`: direct upstream URL.
- `source_authority`: organization responsible for the source.
- `published`: upstream publication date.
- `retrieved_at`: date on which the bundled record was verified.

Module advisories additionally require a CVE, CWE, affected upper bound, fixed version, authentication requirement and business-risk description. Core releases require the PrestaShop release and summary.

## Migration rules

1. Adding an optional field does not change the schema version.
2. Adding a required field, removing or renaming a field, or changing its meaning requires a new integer schema version.
3. Readers must validate known versions explicitly and reject unknown versions.
4. A migration must preserve `record_id`, upstream provenance and original publication date.
5. Migration code requires positive, negative and backward-compatibility fixtures.
6. An advisory content change requires a new snapshot manifest; records must never be silently rewritten after release.

Schema changes and advisory content changes must be reviewed independently from scanner logic whenever practical.

## Snapshot integrity

`advisories/snapshot-manifest.json` lists every advisory record ID and its SHA-256 digest. Regenerate it only after reviewing an advisory change:

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli advisories manifest
```

The normal `advisories validate` command validates both the typed records and the manifest. The SHA-256 manifest detects unreviewed drift; released manifests can additionally be authenticated with a detached Ed25519 signature.

Sign a reviewed release manifest with a private key stored outside the repository:

```powershell
$env:LOGIALOG_SIGNING_PASSWORD = "<set securely in the release environment>"
.\.venv\Scripts\python.exe -m backend.app.cli advisories sign `
  --manifest advisories\snapshot-manifest.json `
  --private-key C:\secure\logialog-ed25519-private.pem `
  --password-env LOGIALOG_SIGNING_PASSWORD `
  --output advisories\snapshot-manifest.sig.json
```

Verify with the published Ed25519 public key:

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli advisories verify-signature `
  --manifest advisories\snapshot-manifest.json `
  --signature advisories\snapshot-manifest.sig.json `
  --public-key keys\logialog-ed25519-public.pem
```

The project never generates or stores the production private key. Key creation, backup, rotation and revocation are owner-controlled release operations. `keys/private/` is ignored as defense in depth, but production private keys should remain outside the checkout.

The public repository includes `keys/logialog-ed25519-public.pem` and the detached `advisories/snapshot-manifest.sig.json`. Their production key ID is `4b563811547e5518`; CI verifies the signature on every change. The encrypted private key and its Windows DPAPI-protected recovery secret are stored outside the checkout and restricted to the owner account.
