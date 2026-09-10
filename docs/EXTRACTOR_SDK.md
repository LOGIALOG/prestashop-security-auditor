# Extractor SDK 1.0

The SDK extends passive fingerprint discovery without weakening the evidence policy. It deliberately provides no package auto-discovery, dynamic path import or remote plugin installation. An operator or reviewed application integration must instantiate and pass a trusted plugin explicitly to `PassiveScanner(plugins=[...])`.

Third-party Python runs with the same local permissions as the auditor. Review its source before activation. The SDK validates output, but it is not a code sandbox.

## Contract

An extractor exposes:

- `plugin_id`: stable lowercase identifier matching `^[a-z0-9][a-z0-9._-]{2,63}$`.
- `api_version`: exactly `1.0`.
- `extract(context)`: returns at most 100 `PluginSignal` objects for one resource.

The read-only context contains the already downloaded URL, response body and content type. Plugins do not receive the HTTP client and cannot ask the scanner for extra requests.

```python
from backend.app.extractor_sdk import ExtractionContext, PluginSignal

class ExampleExtractor:
    plugin_id = "community.example-module"
    api_version = "1.0"

    def extract(self, context: ExtractionContext):
        token = "examplemodule"
        start = context.body.find(token)
        if start < 0:
            return []
        return [PluginSignal(
            kind="active_module",
            name=token,
            confidence="medium",
            method="public-marker",
            start=start,
            end=start + len(token),
        )]
```

## Evidence boundary

Plugins return bounded source positions, not arbitrary evidence objects. The host extracts and redacts the excerpt, redacts the URL, hashes the complete response and namespaces the detection method. Spans are limited to 512 characters.

Community signals support `active_module`, `asset_module` and `theme`, with low or medium confidence. They cannot supply a version and therefore cannot turn an advisory into `CONFIRMED`. Version extractors must first be reviewed and merged into the built-in extractor corpus.

An invalid plugin ID, incompatible API version, exception, oversized output or invalid signal stops the audit. LOGIALOG never silently presents partial plugin coverage as a complete result.

## Contribution requirements

Every extractor pull request must include:

1. One minimal positive fixture and at least one near-miss negative fixture.
2. Reserved `.test`, `.example` or `demo.local` URLs only.
3. A stable detection method and an explanation of why the marker is public and specific.
4. Redaction tests if the marker can appear near query strings, cookies, emails, phone numbers or tokens.
5. A collision test when two module names or versions appear in the same response window.
6. No real response capture, minified vendor bundle, client domain or reusable exploitation payload.

Run `pytest tests/test_extractors.py tests/test_extractor_sdk.py -q`, then the complete validation sequence in [CONTRIBUTING.md](../CONTRIBUTING.md).
