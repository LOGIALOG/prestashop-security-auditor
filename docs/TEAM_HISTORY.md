# Local team history

Database schema version 2 adds an append-only `audit_events` journal. Every new or updated audit receives a system event. Reviewers can add explicit `reviewed`, `remediation_started`, `remediation_completed` or `risk_accepted` events.

Each event records the audit, domain, event type, actor label, UTC timestamp, short note, previous-event hash and its own SHA-256. The chain covers all events in insertion order, so modifying or removing a previous event is detected by verification.

## Add and verify

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli history add AUDIT_ID `
  --actor alice `
  --event reviewed `
  --note "Evidence reviewed"

.\.venv\Scripts\python.exe -m backend.app.cli history verify
```

Notes are limited to one line and 500 characters. Actor labels use a strict 2–80 character identifier format.

## Export

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli history list `
  --audit-id AUDIT_ID `
  --output reports\audit-history.json
```

This is tamper-evident local attribution, not user authentication, access control or a cryptographic identity signature. Organizations needing non-repudiation should sign the resulting report bundle and retain the SQLite database in controlled storage.

Existing audits created before schema version 2 are not backfilled with invented events. Their future updates and reviews are recorded normally.

History notes and exports may contain client context. The database and `reports/*.json` remain Git-ignored.
