# SWOT 2.0 — Smart Website OSINT Tool

A rewrite of the original single-file PHP tool into a **separated
backend / frontend** architecture:

- **backend/** — a FastAPI service that runs each scan as a background *job*
  and streams results live over **Server-Sent Events (SSE)**.
- **frontend/** — a Next.js (TypeScript, App Router) UI that starts scans and
  follows them in real time.

This fork is maintained by [@DeathlyHallow5](https://github.com/DeathlyHallow5)
with the original author's permission. Licensed under **GPL-3.0** (unchanged).

> ⚠️ **Authorized use only.** Reconnaissance tools must only be pointed at
> systems you own or have explicit written permission to test.

## Architecture

```
POST /api/scans                   -> creates a job, returns job_id
GET  /api/scans/{id}/events (SSE) -> live log + findings as they happen
GET  /api/scans/{id}              -> full status + replay of all events
POST /api/scans/{id}/cancel
GET  /api/scanners                -> catalog of available scans
```

Each scanner declares how its target is validated. Validation is the main
security boundary and is covered by tests (`backend/tests/test_targets.py`):

- hostnames are matched against an RFC 1123 pattern (blocks shell injection);
- IP targets must be public (private / loopback / reserved are rejected, an
  SSRF guard);
- URL targets must be `http`/`https` with a non-private host.

## Scanners

| Name             | What it does                                  | Needs       |
| ---------------- | --------------------------------------------- | ----------- |
| `ssl_cert`       | Reads and summarises a host's TLS certificate | pure Python |
| `dns_subdomains` | Resolves a wordlist of subdomains over DNS    | pure Python |

More scanners (ports, WHOIS, HTTP fingerprinting, Wayback) are ported from the
original onto the same job/SSE contract.

## Running locally

### Backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt       # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # Linux/macOS
.venv/Scripts/python -m uvicorn app.main:app --port 8000
```

Run the tests:

```bash
cd backend
.venv/Scripts/python -m pytest -q
```

### Frontend

```bash
cd frontend
npm install
npm run dev   # http://localhost:3000
```

The frontend reads the API base URL from `NEXT_PUBLIC_API_BASE`
(default `http://localhost:8000`), set in `frontend/.env.local`.
