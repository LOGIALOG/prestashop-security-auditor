# Operational preflight

Two network-free commands make the execution boundary reviewable before an audit.

## Readiness check

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli doctor --output reports\doctor.json
```

Required checks cover Python 3.13+, the bundled advisory snapshot, its production Ed25519 signature and repository publication safety. Node.js, npm, PHP, Docker and Git are reported as optional runtime information because direct and containerized execution use different subsets. The report sets `network_access` to `false`; required-check failure returns exit code `12`.

## Scan plan

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli plan https://shop.example --authorized --max-requests 10 --delay 2 --public-page https://shop.example/contact --output reports\scan-plan.json
```

The plan validates the same authorization, URL, request-count and delay constraints as a real scan. It lists required start URLs separately from optional start URLs, then declares the dynamic same-origin asset behavior, GET-only method, redirect boundary and maximum request count. The root and explicit public pages are required; `robots.txt` and dynamically discovered assets are optional. Cross-origin public pages are rejected. Creating the plan does not resolve DNS or send HTTP requests.

The real `scan` command accepts the same repeatable `--public-page` option.
