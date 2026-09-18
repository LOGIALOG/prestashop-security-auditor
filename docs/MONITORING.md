# Scheduled local monitoring

Monitoring is a safe one-shot command designed for a local operating-system scheduler. LOGIALOG does not create a cloud job, daemon, webhook or hidden background process.

Copy [monitor.example.json](monitor.example.json) to the Git-ignored `monitor.local.json`, then replace the reserved domain with the exact authorized public target.

## Safety and notification behaviour

- Explicit authorization is mandatory in every configuration.
- The remote scanner keeps the same same-origin, public-target, GET-only, 20-request and minimum-delay boundaries.
- Each run creates an auditable report. Completed runs compare against the latest previous completed real audit of the same domain; incomplete and legacy records remain stored as evidence but are never comparison baselines.
- The first run creates a quiet `BASELINE`.
- An unchanged run produces `UNCHANGED`, writes its machine-readable result and exits `0` without console output.
- A configured meaningful change produces `CHANGED`, writes reasons and exits `11` so the local scheduler can notify the operator.
- Scan, policy or network errors retain their normal error exit codes and are never reported as an unchanged success.
- An incomplete scan emits monitor-result schema `1.1` with state `INCOMPLETE`, `comparison: null`, and its structured `scan_issues`, then exits `5`. Normal `BASELINE`, `UNCHANGED`, and `CHANGED` results also use schema `1.1`; monitor configuration remains schema `1.0`.

Meaningful changes can include new findings with selected statuses, resolved findings, status/version changes and a score decrease above the configured threshold. Hardening-only noise can be excluded by leaving `HARDENING` out of `notify_on_added_statuses`.

## Baseline payload integrity

New audits are recorded with a SHA-256 digest of the exact stored `audits.payload` text. When a previous completed real audit is selected as the monitoring baseline, its stored payload is hashed and compared to that digest (and the row identity is checked against the payload) before the audit is trusted for comparison.

- A digest mismatch or a malformed digest fails closed; monitoring does not fall back to an older baseline or report a quiet `BASELINE`.
- Completed real baselines recorded before this binding have no digest. Their historical integrity cannot be proven, so no hash is backfilled and they are not trusted as baselines; monitoring fails closed instead of silently treating them as a first run.
- Incomplete, demo and schema-invalid records remain non-baselines as before.

The adjacent SHA-256 detects integrity mismatch or corruption where the stored payload no longer matches its recorded digest. It is not a signature and does not protect against an actor able to rewrite both the payload and its digest in the same database.

## Validate without network access

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli monitor validate --config monitor.local.json
```

## Scheduler command

Configure Windows Task Scheduler, cron or another local runner to invoke:

```powershell
C:\absolute\path\.venv\Scripts\python.exe -m backend.app.cli monitor run `
  --config C:\absolute\path\monitor.local.json `
  --output C:\absolute\path\reports\monitor-result.json
```

Run it with the repository as the working directory. Configure notifications for exit code `11` and failures for other non-zero codes. Do not publish `monitor.local.json`, the SQLite history, reports or monitoring results.
