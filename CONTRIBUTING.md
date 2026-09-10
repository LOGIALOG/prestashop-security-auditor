# Contributing

Contributions are welcome when they preserve the evidence-first and safe-by-default design.

## Before opening a pull request

1. Do not scan a real shop for a test or fixture.
2. Use only `demo.local`, reserved `.test`, `.example` or `.invalid` domains in fixtures.
3. Never include reports, databases, credentials, tokens, customer data or captured third-party responses.
4. Keep remote checks passive, same-origin, GET-only, rate-limited and authorization-gated.
5. A real finding requires captured evidence and must preserve uncertainty when a version is unknown.
6. Advisory imports remain pending until manually reviewed and promoted.
7. Screenshots must show only `demo.local` or fully synthetic reserved-domain data; crop browser history, accounts, paths and unrelated applications.

Run:

```powershell
.\.venv\Scripts\python.exe -m backend.app.cli repository validate
.\.venv\Scripts\python.exe -m backend.app.cli advisories validate
.\.venv\Scripts\python.exe -m pytest tests -q
cd frontend
npm test
npm run build
```

Use Conventional Commits with `feat`, `fix` or `refactor`. Keep scanner logic, advisory-data updates and generated manifest changes reviewable.

Extractor contributions must follow the typed SDK boundary and fixture checklist in [docs/EXTRACTOR_SDK.md](docs/EXTRACTOR_SDK.md). Community plugins are never auto-loaded, cannot request additional URLs and cannot assert a trusted version. Built-in extractor changes require both positive and near-miss negative corpus cases.

Security vulnerabilities must follow [SECURITY.md](SECURITY.md), not a public issue.
