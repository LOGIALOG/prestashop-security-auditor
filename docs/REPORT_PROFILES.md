# White-label report profiles

A report profile changes presentation only. It cannot change findings, evidence, scoring, the permanent demo watermark, or LOGIALOG engine provenance.

## Schema 1.0

Use [report-profile.example.json](report-profile.example.json) as the starting point. Supported fields:

- `schema_version`: required compatibility marker; currently `1.0`.
- `brand_name`: visible agency or team name, up to 80 characters.
- `report_title`: visible title for real reports, up to 120 characters.
- `primary_color` and `accent_color`: strict `#RRGGBB` values.
- `contact_url`: optional absolute HTTP(S) URL.
- `logo_data_uri`: optional embedded PNG, JPEG or WebP, valid base64 and at most 256 KiB decoded.

SVG logos, remote image URLs, HTML, CSS fragments, control characters and unknown fields are rejected. Keeping the logo embedded makes the report portable and prevents a generated report from contacting a third-party image host when opened.

## Render a report

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli report render AUDIT_ID `
  --profile docs\report-profile.example.json `
  --output reports\client-report.html
```

The output command returns the canonical report SHA-256. Every generated HTML file includes immutable `generator`, `logialog:engine`, `logialog:engine-version` and profile-schema metadata. White-label presentation therefore does not hide which engine produced the security assessment.

Profiles should contain reusable agency identity only. Do not commit client names, domains, contacts, credentials or report outputs.
