# Project positioning

This document records the strategic positioning of the PrestaShop Security
Auditor. It is internal-readable context that also explains how the public
project supports LOGIALOG's security engineering practice.

## 1. Project purpose

The PrestaShop Security Auditor is an open-source proof of LOGIALOG's expertise
in PrestaShop security. Its primary objective is not to be sold as a standalone
scanner product; the repository is a public demonstration of how the team
approaches security engineering.

The project supports service areas such as:

- PrestaShop security auditing;
- security hardening;
- module security review;
- maintenance and monitoring;
- e-commerce security engineering.

## 2. Open-source strategy

The public repository exists to provide:

- **transparency** — the checks, limits and evidence model are inspectable;
- **technical credibility** — behavior is demonstrated by code and tests;
- **engineering proof** — verifiable, reproducible implementation;
- **community visibility** — a shared reference for PrestaShop practitioners;
- **educational value** — a basis for documentation, articles and training.

## 3. Differentiation: evidence-first philosophy

The core differentiator is an evidence-first approach to security auditing. The
objective is not only to detect issues, but to produce:

- **explainable findings** — each conclusion is described and justified;
- **traceable evidence** — findings reference the observations they rest on;
- **reproducible verification** — results can be re-derived and checked;
- **confidence-based decisions** — outputs distinguish confirmed, uncertain and
  not-tested states instead of implying certainty.

Security conclusions should be supported by verifiable evidence. Where evidence
is missing, failed or incomplete, the project reports that uncertainty rather
than asserting a safe or exploited condition.

## 4. Business relationship

The open-source project is not the final commercial product. It acts as the top
of a funnel:

```text
Open Source Project
        |
        v
Technical Authority
        |
        v
SEO Visibility
        |
        v
Client Trust
        |
        v
Security Services
```

The project builds technical authority and visibility, which in turn support
trust and the delivery of security services.

## 5. Decision criteria

Future technical decisions should be evaluated against a single question:

> Does this improve security trust, technical credibility, or client value?

Features or changes that only increase complexity without improving these goals
should be carefully evaluated and, by default, avoided.

## Public-safety note

This document intentionally contains no private client information, internal
incidents, credentials, production details or confidential business data.
