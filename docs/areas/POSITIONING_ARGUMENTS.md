# Product positioning argument register

This file is the shared reference for discussing LOGIALOG PrestaShop Security Auditor. It separates verified product behaviour from hypotheses that still need empirical evidence.

## Canonical positioning

LOGIALOG Auditor is a PrestaShop-specific, evidence-first triage tool for explicitly authorized assessments. It observes a deliberately bounded public surface and can correlate trusted local source metadata with reviewed advisories. It complements, but does not replace, authenticated testing, SAST, SCA, active scanners or manual penetration testing.

## Claims we can defend today

- Remote scans use GET only, remain on the exact origin, follow no cross-origin redirect, wait at least one second between requests and stop at a maximum of 20 requests.
- The tool requires two operator confirmations in the dashboard and an explicit authorization flag in the CLI/API model.
- These confirmations record self-attestation. The tool does not technically prove domain ownership or the legal authority of the operator.
- GET-only and bounded execution significantly reduce operational risk compared with active exploitation-oriented scanning. They do not eliminate traffic, logging, WAF, rate-limit or SOC effects.
- Public observations may expose module paths, version strings, frontend assets, HTTP headers, cookie attributes and other evidence returned by the authorized target.
- A public fingerprint is treated according to its evidence quality. An unknown version or asset residue is not converted into a confirmed vulnerability.
- Local assessment hashes the exact metadata file used for a detected version and does not execute inspected source code.
- Advisory records have typed schemas, source provenance, retrieval dates, deterministic snapshot hashes and a published Ed25519 signature.
- Advisory additions are review-only; remote sources cannot silently modify the trusted snapshot.

## Claims we must not make

- Do not claim that most PrestaShop compromises are detectable from the public surface without a cited, representative dataset.
- Do not claim that the tool detects exposed `.env`, configuration files, admin folders or arbitrary routes unless a dedicated bounded check is implemented and tested.
- Do not say that an audit can run without the target owner's authorization.
- Do not describe self-attested authorization as technical ownership verification.
- Do not promise zero production risk.
- Do not present confidence labels as statistically calibrated probabilities.
- Do not claim that an affected version proves exploitation or compromise.
- Do not claim that a clean result means a penetration test is unnecessary.
- Do not call the advisory coverage comprehensive or continuously updated without a documented service level and measured coverage.
- Do not dismiss ZAP, Nuclei, SAST or SCA as tools that only produce probabilities; their scope and evidence models differ.

## Known limitations

### Authorization

Authorization is contractual and legal. The product records the operator's declaration and applies safety boundaries, but it cannot independently establish ownership of a remote domain. Stronger proof such as a DNS or HTTP challenge would be a separate opt-in capability and is not implemented.

### Operational risk

The scanner sends real HTTP requests. Even bounded GET requests can consume resources, enter access logs, trigger a WAF or be classified as suspicious by a SOC. The defensible claim is reduced operational risk, never absence of risk.

### Fingerprinting

CDNs, stale caches, customized modules, removed version strings and deliberate spoofing can affect public fingerprints. Confidence levels describe the strength and type of captured evidence; they are not empirically calibrated probabilities. Local metadata or authenticated Back Office evidence remains stronger than an asset-only signal.

### Advisory coverage

The trusted advisory set is intentionally small today. “Reviewed” means schema-validated, source-attributed, manifest-hashed and manually accepted before publication. It does not yet imply a fixed update frequency, exhaustive ecosystem coverage or independent reproduction of every upstream vulnerability.

## Evidence backlog

Before making stronger quantitative claims, collect a consented and anonymized validation corpus that includes:

1. Supported PrestaShop major versions and representative hosting/CDN configurations.
2. Official, custom, outdated, renamed and cache-stale module examples.
3. Ground-truth versions obtained from local metadata or authenticated Back Office access.
4. Per-extractor true positives, false positives, false negatives and indeterminate outcomes.
5. Request counts, WAF/SOC observations and operational incidents during authorized scans.
6. Advisory coverage by module popularity, publication source, severity and time-to-review.

Only after publishing the methodology and sample limitations may the project describe precision, recall, calibration or ecosystem coverage numerically.

## Senior objections and precise responses

### “Passive and GET-only is too limited.”

Correct: the remote mode is intentionally limited. It provides a low-impact, reproducible first layer for public evidence and prioritization. Deeper authenticated and active testing remains necessary when the engagement requires it.

### “A checkbox does not prove authorization.”

Correct. It records self-attestation and makes the obligation explicit; it is not ownership verification. Same-origin, GET-only, delay and request-budget controls reduce abuse potential but do not replace legal authorization.

### “GET requests can still affect production.”

Correct. The risk is reduced, not zero. Operators must coordinate with the owner, respect monitoring procedures and stop when the target shows instability or defensive blocking.

### “Fingerprint confidence is meaningless without calibration.”

Confidence currently represents an evidence-quality category, not a probability. The report exposes the source, method and limitations so a reviewer can challenge it. Statistical calibration remains an evidence-backlog item.

### “Curated just means small.”

The current defensible term is “reviewed and provenance-tracked.” The process is public and deterministic, while breadth and update frequency remain limited until measured and documented.

## Approved short pitch

> LOGIALOG Auditor provides bounded, evidence-backed PrestaShop triage for authorized assessments. It reduces operational risk compared with active scanning, makes uncertainty visible and connects public observations to local remediation workflows. It does not prove ownership, guarantee zero impact or replace a full security assessment.

## Maintenance rule

Update this register whenever a capability, safety boundary, advisory process or validation dataset changes. New marketing or technical claims must link to code, tests, documentation or a named external source; otherwise they remain hypotheses in the evidence backlog.
