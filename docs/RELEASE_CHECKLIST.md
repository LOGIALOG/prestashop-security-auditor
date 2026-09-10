# Local release-readiness checklist

## Safety and privacy

- [x] Final repository URL confirmed as `https://github.com/logialog/prestashop-security-auditor` and SARIF metadata updated.
- [x] Repository safety gate passes.
- [x] No real-shop domain is present in publishable source or fixtures; local ignored artifacts remain outside Git.
- [x] Reports, SQLite databases, JSON exports, review candidates and `.env` are ignored.
- [x] Docker build contexts exclude local reports, secrets, private keys, virtual environments and frontend artifacts.
- [x] Demo data is restricted to `demo.local` and visibly marked.
- [x] README screenshots contain only synthetic `demo.local` and reserved `example.test` data.
- [x] Remote scanning remains authorization-gated, same-origin, GET-only and bounded.

## Data and contracts

- [x] Advisory typed validation and snapshot integrity pass.
- [x] Advisory ingestion produces pending review candidates only.
- [x] JSON, SARIF and CycloneDX contracts are documented and tested.
- [x] Local source and archive operations are offline and do not execute inspected code.
- [x] Add detached Ed25519 signing and public-key verification for released advisory manifests.
- [x] Pin direct frontend dependencies and verify a clean deterministic `npm ci` install.

## Community and legal

- [x] Contribution guide, pull-request checklist and safe issue forms exist.
- [x] Responsible-disclosure guidance exists.
- [x] Code of conduct exists.
- [x] Repository owner approved Apache License 2.0; canonical `LICENSE` and LOGIALOG `NOTICE` files are present.
- [x] Repository owner selected GitHub Private Vulnerability Reporting as the official security-report channel.
- [x] Enable Private Vulnerability Reporting in the public repository security settings.
- [x] Enable dependency vulnerability alerts and automatic security fixes.

## Final verification

- [x] Run the complete backend suite on Python 3.13 (122 tests).
- [x] Run frontend tests and production build on Node.js 22.
- [x] Add a localhost-only Docker Compose build and runtime smoke job to GitHub CI.
- [x] Validate all GitHub workflow and issue-template YAML in the backend test suite.
- [x] Run the Docker Compose smoke test on a GitHub-hosted Docker runner.
- [x] Run repository, advisory, backend, frontend, Chromium and PHP gates from a clean checkout.
- [x] Review `git status`; no files are staged and generated local artifacts are ignored.
- [x] Repository owner authorized autonomous local completion and a local release commit.
- [x] Obtain explicit approval before public repository creation and the first push.
- [x] Protect remote `main` with required backend, frontend and container checks; block force-push and deletion.
- [x] Obtain explicit approval before creating a versioned GitHub Release or tag.
- [x] Generate the encrypted production Ed25519 key outside the checkout and publish only its public key.
- [x] Sign the released advisory snapshot and verify its detached signature in CI.
