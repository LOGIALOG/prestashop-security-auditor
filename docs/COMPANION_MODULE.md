# Optional PrestaShop companion module

`companion/logialogsecuritybridge` is an optional PrestaShop 1.7.8–8.x module. It provides one authenticated read-only inventory endpoint when public evidence cannot confirm installed versions or multistore configuration.

The endpoint returns only:

- PrestaShop core version;
- enabled module technical names and versions;
- shop identifiers, names, public base URLs and active state;
- schema version and UTC generation time.

It never returns customers, orders, carts, employees, emails, addresses, sessions, database settings, configuration values, credentials or the HMAC secret. It performs no write during inventory requests.

## Install and configure

1. Package the `companion/logialogsecuritybridge` directory as `logialogsecuritybridge.zip` with the module directory at the archive root.
2. Install it from the authorized PrestaShop Back Office module manager.
3. Open the module configuration page and use **Rotate and reveal secret once**.
4. Copy the 64-character secret to a secure local secret store. It is not displayed again unless rotated.
5. Copy the HTTPS endpoint shown by the module.

The initial install creates a random secret. Rotating invalidates the previous value immediately. Uninstalling deletes it.

## Authentication protocol 1.0

The client sends a GET request with:

- `X-Logialog-Timestamp`: current Unix timestamp;
- `X-Logialog-Signature`: lowercase HMAC-SHA256 of `GET`, the exact URL path and timestamp separated by line feeds.

Requests outside a five-minute window, invalid signatures, non-GET methods and non-HTTPS access are rejected. The short replay window is acceptable because the authenticated operation is strictly read-only; rotate the secret after any suspected disclosure.

The LOGIALOG client requires explicit `--authorized`, reads the secret only from an environment variable, refuses redirects and responses above 1 MiB, and validates every response field with a strict schema.

```powershell
$env:LOGIALOG_COMPANION_SECRET = "<secret>"
.\.venv\Scripts\python.exe -m backend.app.cli companion fetch `
  --endpoint https://shop.example/module/logialogsecuritybridge/inventory `
  --secret-env LOGIALOG_COMPANION_SECRET `
  --authorized `
  --output reports\companion-inventory.json
```

Treat the inventory as confidential client data. Report outputs are ignored by Git. Never commit the secret, a real endpoint or a captured inventory.
