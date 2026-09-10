# Signed report bundles

A signed bundle is a portable delivery ZIP tied to one recorded audit. It contains exactly:

- `report.html`: client report with immutable LOGIALOG engine metadata and permanent demo watermark when applicable.
- `audit.json`: portable LOGIALOG JSON without local filesystem paths.
- `audit.sarif`: SARIF 2.1.0 for CI and security tools.
- `advisory-snapshot.json`: advisory snapshot provenance used by this release.
- `bundle-manifest.json`: canonical file sizes, SHA-256 hashes, audit identity, engine version and report-profile schema.
- `bundle-manifest.sig.json`: detached Ed25519 signature envelope.

Creation is deterministic for the same audit, profile and key. An existing destination is never overwritten.

## Create

Keep the private key outside the checkout. For an encrypted PEM, place its password in an environment variable and add `--password-env VARIABLE_NAME`.

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli bundle create AUDIT_ID `
  --output reports\audit-bundle.zip `
  --private-key C:\secure\logialog-private.pem `
  --password-env LOGIALOG_SIGNING_PASSWORD `
  --profile docs\report-profile.example.json
```

LOGIALOG does not generate, copy or retain private keys.

## Verify

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli bundle verify `
  --bundle reports\audit-bundle.zip `
  --public-key C:\public\logialog-public.pem
```

Verification runs in memory and does not extract archive content. It rejects unexpected or duplicate entries, wrong ordering, encrypted entries, oversized content, hash mismatch, signature mismatch, audit-identity mismatch, missing provenance and missing demo watermark.

Bundles contain audit evidence URLs and excerpts. Treat real bundles as confidential client deliverables; `reports/*.zip` is ignored and blocked from repository publication.
