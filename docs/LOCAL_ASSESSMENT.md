# Offline local advisory assessment

`source assess` correlates versions found in a user-selected PrestaShop checkout with an advisory snapshot whose SHA-256 manifest has been verified. It performs no network request and never loads or executes PHP, Composer scripts or module code.

## Usage

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli source assess C:\path\to\prestashop --format json --output reports\local-assessment.json
.\.venv\Scripts\python.exe -m backend.app.cli source assess C:\path\to\prestashop --format sarif --output reports\local-assessment.sarif --fail-on-affected
.\.venv\Scripts\python.exe -m backend.app.cli source assess C:\path\to\prestashop --format cyclonedx --output reports\local-assessment.cdx.json
```

Pass `--advisories C:\path\to\snapshot` to use another reviewed snapshot. The directory must contain valid advisory records and a matching `snapshot-manifest.json`; modified, missing or extra records are rejected.

## Local source inventory and code review

Two read-only local commands support assessment without network access or code execution:

```powershell
# Deterministic source inventory (core, modules, Composer)
.\.venv\Scripts\python.exe -m backend.app.cli source scan C:\path\to\prestashop --format cyclonedx --output reports\sbom.json

# PHP patterns requiring manual review (rule, path, line, confidence)
.\.venv\Scripts\python.exe -m backend.app.cli source review C:\path\to\prestashop --output reports\code-review.json
```

`source scan` exports no file contents and never invents a missing version. `source review` returns bounded signals only and never turns a signal into a confirmed vulnerability.

## State semantics

- `AFFECTED`: the detected module version falls within the published affected range and its metadata file has recorded SHA-256 evidence. This is a remediation signal, not proof that the shop was exploited.
- `NOT_AFFECTED`: the detected version is at or above the published fixed version.
- `INDETERMINATE`: a component or advisory matches by name but reliable version evidence is unavailable.
- `UPDATE_RECOMMENDED`: the detected PrestaShop core version is older than a reviewed core security release. It is maintenance guidance and does not assert a specific CVE.
- `CURRENT_OR_NEWER`: the local core version is at least the reviewed release.

JSON preserves the complete inventory, snapshot digest, evidence paths and hashes. SARIF maps advisory matches to the local metadata files used as evidence. CycloneDX 1.6 uses stable component BOM references and vulnerability analysis states. Consumers must preserve these states instead of converting all matches into confirmed vulnerabilities.

Exit code `10` is returned only when `--fail-on-affected` is supplied and at least one `AFFECTED` match exists. Unknown or maintenance-only states do not fail that gate.
