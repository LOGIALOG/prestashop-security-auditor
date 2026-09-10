# Multistore inventory and scope

The multistore manifest is an explicit operator-owned inventory. LOGIALOG does not read a PrestaShop database, configuration secrets or back-office data to discover shops.

Copy [multistore.example.json](multistore.example.json) to `multistore.local.json`, then replace the reserved example domains with the exact authorized public shop URLs. The local filename is ignored by Git because it may contain client identity.

## Safety boundaries

- `authorization_confirmed` must be `true` for the complete batch.
- One manifest supports at most 10 shops and 100 requested GETs in total.
- Every shop remains capped at 20 GET requests with at least one second between requests.
- Explicit public pages must share the exact scheme, host and port of their shop target.
- Shops run sequentially in isolated scanner instances; findings, evidence, scope and report hashes are never merged.
- Private, loopback, link-local and reserved network targets remain rejected by the remote scanner.
- The portable batch export excludes local report paths.

## Validate without network access

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli multistore validate --manifest multistore.local.json
```

Validation checks the schema, authorization, shop identifiers, origins and request budget. It sends no request.

## Run the authorized batch

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli multistore scan `
  --manifest multistore.local.json `
  --output reports\multistore-audit.json `
  --fail-on-confirmed
```

The optional policy flag returns exit code `10` when any shop has a confirmed finding. A network or policy failure stops the batch instead of returning a partial success that could be mistaken for complete coverage.

Do not commit `multistore.local.json`, exported results or generated HTML reports.
