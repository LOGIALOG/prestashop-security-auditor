# LOGIALOG PrestaShop Security Auditor v1.0.0

The first public release provides a local-first, evidence-first security workflow for authorized PrestaShop assessments.

## Highlights

- Authorization-gated passive scanning: GET-only, same-origin, delayed and limited to 20 requests.
- Evidence-backed HTML, portable JSON and SARIF 2.1.0 reports with explicit uncertainty states.
- Offline local checkout inventory, conservative PHP review signals and CycloneDX 1.6 SBOM export.
- Manifest-verified advisory correlation with local file hashes and affected, fixed or indeterminate states.
- Signed advisory snapshots and signed delivery bundles using Ed25519.
- White-label reports, isolated multistore execution, policy packs, monitoring and append-only team history.
- French, English and Arabic dashboard support, including RTL and accessibility regression coverage.
- Network-free `doctor` readiness checks and authorization-gated scan planning.

## Safety boundaries

This release does not perform exploitation, brute force, authentication bypass, POST requests or cross-origin crawling. A detected component or affected version is a remediation signal, not evidence that a shop was exploited. Use the tool only on shops you own or are explicitly authorized to assess.

## Verification

The release candidate passes 121 backend tests, 6 frontend tests, 3 Chromium accessibility/responsive tests, deterministic frontend build checks and localhost-only Docker Compose smoke tests. GitHub CI also validates repository safety, advisory integrity and the production advisory snapshot signature.

Production advisory signing key ID: `4b563811547e5518`.
