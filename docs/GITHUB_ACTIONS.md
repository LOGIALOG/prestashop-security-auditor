# GitHub Actions

The repository CI validates advisory provenance, runs the backend tests, runs the frontend tests and produces a frontend build. It never scans an external website.

Project repository: [logialog/prestashop-security-auditor](https://github.com/logialog/prestashop-security-auditor). The public CI definition is available in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).

## SARIF publishing

Remote audits must not run automatically on public GitHub-hosted runners. A repository owner may run an explicitly authorized scan from a trusted or self-hosted environment, save `audit.sarif`, and upload it in a private workflow with:

```yaml
permissions:
  security-events: write

steps:
  - name: Upload authorized audit SARIF
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: audit.sarif
```

The scan step should retain the CLI `--authorized` gate, a fixed organization-controlled target and the default request limit. Do not expose a free-form public target input.
