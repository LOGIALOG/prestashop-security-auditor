# Competitive analysis

Research snapshot: 2026-09-06. This document compares product behaviour, not marketing claims.

## Existing approaches

| Tool | Delivery model | Strengths | Gap LOGIALOG can address |
| --- | --- | --- | --- |
| PrestaScan Security | Installed PrestaShop module connected to an external service | Known module/core vulnerabilities, unused modules, exposed directories and alerts | No-install external assessment, local-first operation, explicit evidence provenance and CI exports |
| MyPresta Security Scan | Installed module, scan performed inside the shop | Private local analysis and unused-code detection | Independent passive view before privileged access and reproducible evidence bundle |
| zapalm vulnerability checker | Standalone open-source checker | Small, understandable known-vulnerability checker | Broader evidence model, confidence states, maintained advisory ingestion and developer workflow |
| ps-scan | External open-source scanner | Public module/version discovery and CVE checks | Strict safe-by-default policy, authorization gates, rate limit, same-origin boundary and auditable findings |
| Friends of Presta advisories | Public advisory database | Valuable PrestaShop module vulnerability intelligence | Offline signed snapshots, normalization, source provenance and automated matching |
| Generic SAST/SCA tools | Repository and dependency scanning | Mature CI, SARIF and pull-request workflows | PrestaShop-specific hooks, modules, overrides, configuration and remediation knowledge |

## Product position

LOGIALOG should not compete on “more aggressive scanning”. Its defensible position is a trustworthy bridge between a passive shop assessment and a developer remediation workflow:

1. Every real conclusion is tied to captured evidence, time, URL, hash, extractor and confidence.
2. Unknown versions stay unknown; asset residue never becomes a fabricated vulnerability.
3. The remote mode remains GET-only, rate-limited and same-origin.
4. A separate trusted local-source mode provides inventory, review signals and manifest-verified advisory correlation without exposing the shop.
5. Outputs are portable: HTML for clients, JSON for automation and SARIF for CI/security tooling.
6. Advisory data is versioned, attributable, reproducible and usable offline.

## High-value feature gaps

### Delivered from the study

- [x] JSON and SARIF exports with complete evidence provenance.
- [x] CLI/headless execution with stable exit codes and policy profiles.
- [x] Advisory schema validation, snapshot metadata and update provenance.
- [x] False-positive regression corpus for module/version extractors.
- [x] Diff between two real audits, never between demo and real data.
- [x] Trusted local source-tree scan, CycloneDX SBOM and conservative PHP review signals.
- [x] Manifest-verified offline matching between local module versions and reviewed advisories.
- [x] GitHub Actions example, multistore isolation and signed evidence bundles.
- [x] Network-free readiness diagnostics and exact scan-scope planning before execution.

### Keep out of remote mode

- Exploit payloads, brute force, authentication bypass attempts and destructive checks.
- Cross-origin crawling, uncontrolled route enumeration and automatic scanning of arbitrary targets.
- Claims based only on a module directory name or frontend asset residue.

## Sources

- PrestaScan product: https://www.prestascan.com/en/content/76-prestascan-security
- PrestaScan source: https://github.com/prestascan/prestascansecurity
- MyPresta Security Scan: https://mypresta.rocks/security-scan
- zapalm checker: https://github.com/zapalm/prestashop-security-vulnerability-checker
- ps-scan: https://github.com/jakub-przepiora/ps-scan-Prestashop-scanner
- Friends of Presta advisories: https://security.friendsofpresta.org/
- PrestaShop security release process: https://www.prestashop-project.org/security/security-release-process/
