# Certificate Corpus Inputs

## Current Corpora

### `tranco_1m/`
**TLS certificates from Tranco Top 1M domains**

- **Unique PEM files**: 47,791
- **Manifest rows**: 153,275
- **Collection date**: 2026-07-02
- **Method**: TLS connection to Tranco Top 1M domains with `www` fallback
- **Coverage**: first 60,000 attempted domains
- **TLS chain collection**: enabled via `openssl s_client -showcerts`

### `ct_recent/`
**Recent certificates from Google CT log (Argon 2026 H1)**

- **Unique PEM files**: 63,327
- **Manifest rows**: 122,034
- **Collection date**: 2026-07-02
- **CT log**: https://ct.googleapis.com/logs/us1/argon2026h1/ct/v1/
- **Log tree size at collection**: 2,807,498,988 entries
- **Entry range requested**: 2,807,358,988 - 2,807,488,988
- **Includes pre-certificates**: Yes
- **Includes issuer-chain certificates from CT `extra_data`**: Yes

## Directory Structure

```
tranco_1m/
  ├── certs/              # 47,791 PEM files
  ├── manifest.jsonl      # Per-certificate metadata
  └── run_meta.json       # Collection metadata

ct_recent/
  ├── certs/              # 63,327 PEM files
  ├── manifest.jsonl      # Per-certificate metadata
  └── run_meta.json       # Collection metadata
```

Only these current input corpora are retained. Probe, smoke, and older split
corpora are intentionally not kept in this directory.
