# Documentation

Entry point for the PrestaShop Security Auditor documentation. The sections
below map the repository documentation by purpose.

## Architecture

How the auditor is designed and how its contracts fit together.

- [Security architecture decisions](SECURITY_ARCHITECTURE_DECISIONS.md) — durable decision record, invariants and schema/versioning contracts.
- [Export contract](EXPORT_CONTRACT.md) — JSON, SARIF and compatibility rules for exported artifacts.
- [Positioning arguments](areas/POSITIONING_ARGUMENTS.md) — product positioning and argument register.

## Security

Advisory handling, policy gates and validation governance.

- [Advisory review](ADVISORY_REVIEW.md) — how external material is proposed, reviewed and promoted.
- [Advisory schema](ADVISORY_SCHEMA.md) — advisory record schema and data rules.
- [Policy packs](POLICY_PACKS.md) — versioned release gates and `PASS`/`FAIL`/`UNKNOWN` decisions.
- [Validation protocol](VALIDATION_PROTOCOL.md) — scientific validation approach.
- [Validation governance](VALIDATION_GOVERNANCE.md) — governance rules for validation rehearsals.

## Operations

Running the tool, monitoring, delivery and day-to-day usage.

- [Operational preflight](OPERATIONAL_PREFLIGHT.md) — local readiness check and scan planning.
- [Monitoring](MONITORING.md) — scheduled local checks and change signaling.
- [Multistore](MULTISTORE.md) — isolated, sequential multi-shop auditing.
- [GitHub Actions](GITHUB_ACTIONS.md) — CI usage and SARIF integration.
- [Report profiles](REPORT_PROFILES.md) — white-label report configuration.
- [Report bundles](REPORT_BUNDLES.md) — signed delivery bundles.
- [Companion module](COMPANION_MODULE.md) — optional authenticated inventory endpoint.
- [Team history](TEAM_HISTORY.md) — chained local review journal.
- [Local assessment](LOCAL_ASSESSMENT.md) — offline advisory correlation for a local checkout.
- [Extractor SDK](EXTRACTOR_SDK.md) — bounded extractor plugins.
- [Release checklist](RELEASE_CHECKLIST.md) — release preparation steps.
- [Release notes v1.0.0](RELEASE_NOTES_v1.0.0.md) — release notes.
- [Release readiness report](RELEASE_READINESS_REPORT.md) — release readiness assessment.

## Strategy

Positioning, planning and comparative context.

- [Project positioning](strategy/PROJECT_POSITIONING.md) — purpose, open-source strategy and evidence-first differentiation.
- [Competitive analysis](COMPETITIVE_ANALYSIS.md) — comparison with existing tools.
- [Night plan](NIGHT_PLAN.md) — planning notes.

## Project documents

- [README](../README.md) — project overview and quick start.
- [Security policy](../SECURITY.md) — vulnerability reporting.
- [Contributing](../CONTRIBUTING.md) — contribution guide.
- [Code of conduct](../CODE_OF_CONDUCT.md).
- [Roadmap](../ROADMAP.md).
- [License](../LICENSE).
