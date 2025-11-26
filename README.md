# IoC Manager — Flask API

IoC Manager is a lightweight enrichment & blocking API for Indicators of Compromise (IoCs).  
It aggregates results from multiple security providers and exposes simple HTTP endpoints (used by a Chrome extension or any client).

---

## Features

- **Enrichment**
  - VirusTotal, AlienVault OTX, AbuseIPDB, DNSDB
  - Microsoft Defender for Endpoint (Advanced Hunting / TI)
  - MISP (search)
  - EDL (external destination list)
- **Blocking**
  - MISP: create/append events, add attributes, tag with TLP
  - Cisco Umbrella: manage destination lists (optional)
  - EDL: push IoCs to a configurable list
- **Config model**
  - Per-request API keys from clients **or** server-side environment-variable fallbacks
- **Reliability**
  - Explicit HTTP timeouts on outbound requests
  - Minimal, masked logging

---

## Prerequisites

- Python 3.10+ (recommended)
- An account/API key for the providers you plan to use
- (Optional) Azure App Service for deployment

---

## Quick start (local)

```bash
# from repo root
cd app

python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt

# Non-secrets
export FLASK_ENV=development
export MISP_BASE_URL=https://misp.example.org
export DNSDB_BASE_URL=https://dnsdb.sie-europe.net/dnsdb/v2

# Optional server-side keys (clients may also send per-request keys)
export OTX_API_KEY=...
export ABUSEIPDB_API_KEY=...
export VIRUSTOTAL_API_KEY=...
export DNSDB_API_KEY=...

# Microsoft Defender (required for Defender features)
export DEFENDER_TENANT_ID=<guid>
export DEFENDER_CLIENT_ID=<guid>
export DEFENDER_CLIENT_SECRET=<secret>
export DEFENDER_SCOPE=https://api.security.microsoft.com/.default

# Run the API:
python api.py
# API listens on http://127.0.0.1:5000

# Health check:
curl http://127.0.0.1:5000/health
```

## Configuration model

Clients (e.g., the Chrome extension) can send per-request credentials in the JSON body.  
If a key or base URL is omitted/empty, the server falls back to environment variables.

### API key precedence
1. `api_keys.<provider>.apiKey` in the request (non-empty)
2. Server env var (for example, `OTX_API_KEY`)

### Base URL precedence
1. `api_keys.<provider>.baseUrl` in the request (non-empty)
2. Server env var (for example, `DNSDB_BASE_URL`)

This allows central admin-run configuration while still supporting user-provided keys.

---

## Environment variables

### Non-secret (endpoints / flags)
- `MISP_BASE_URL` (for example, `https://misp.example.org`)
- `MISP_VERIFY_SSL` (`true`/`false`)
- `DNSDB_BASE_URL` (for example, `https://dnsdb.sie-europe.net/dnsdb/v2`)
- `DNSDB_VERIFY_SSL` (`true`/`false`)
- `FLASK_ENV` (`development`/`production`)

### Secrets (optional server-side fallbacks)
- `MISP_API_KEY`
- `DNSDB_API_KEY`
- `OTX_API_KEY`
- `ABUSEIPDB_API_KEY`
- `VIRUSTOTAL_API_KEY` (or `VT_API_KEY`)
- `EDL_API_KEY`
- `UMBRELLA_CLIENT_ID`, `UMBRELLA_CLIENT_SECRET` (if using Umbrella)

### Microsoft Defender
- `DEFENDER_TENANT_ID`
- `DEFENDER_CLIENT_ID`
- `DEFENDER_CLIENT_SECRET`
- `DEFENDER_SCOPE` (usually `https://api.security.microsoft.com/.default`)

---

## API

### `GET /health`
Simple health probe.

```bash
curl http://127.0.0.1:5000/health
```
### `POST /enrich`
Enrich a list of IoCs across configured providers.

Request body (example):

```bash
{
  "ioc_values": ["ku.dk", "1.1.1.1", "http://example.com/"],
  "verbose": false,
  "api_keys": {
    "misp": { "apiKey": "", "baseUrl": "https://misp.example.org" },
    "dnsdb": { "apiKey": "", "baseUrl": "https://dnsdb.sie-europe.net/dnsdb/v2" },
    "abuseipdb": { "apiKey": "" },
    "otx": { "apiKey": "" },
    "virustotal": { "apiKey": "" },
    "edl": { "apiKey": "", "baseUrl": "https://edl.example.com" },
    "umbrella": { "apiKey": "", "apiSecret": "" }
  }
}
```

Curl:

```bash
curl -X POST http://127.0.0.1:5000/enrich \
  -H "Content-Type: application/json" \
  -d '{"ioc_values":["1.1.1.1"],"api_keys":{"abuseipdb":{"apiKey":""}}}'
```
>Provider errors/timeouts are returned per-source; the endpoint returns 200 with best-effort results unless the input is invalid.

### `POST /misp/block`
Create or append a MISP event, add an attribute, and tag with TLP.

Request body (example):
```bash
{
  "ioc": "malicious.example",
  "ioc_type": "domain",
  "comment": "Blocked via Chrome Extension",
  "tlp": "tlp:red",
  "first_name": "Alice",
  "last_name": "Analyst",
  "organization": "Example Org",
  "email": "alice@example.org",
  "api_key": "…",
  "base_url": "https://misp.example.org",
  "verify_ssl": true
}
```
Response (success):
```bash
{ "success": true, "event_id": "12345", "attribute_id": "67890" }
```
Failure:
```bash
Invalid input → 400 with { "error": "..." }

Provider/server errors → 400 or 500 with { "error": "..." }
```
---
## Deployment (Azure App Service)

1. In __Configuration → Application settings__, set the environment variables listed above.
2. Set __FLASK_ENV=production__.
3. Save and restart the app.
4. Verify __/health__, then test __/enrich__.
