# SWOT 2.1 — Smart Website OSINT Tool

A local reconnaissance workspace with a Next.js dashboard, FastAPI job runner,
persistent SQLite history and optional external scanning engines.

## What's new

- Responsive charcoal / mint dashboard: overview, scans, searchable history and engine inventory.
- Live findings, progress and activity; reconnectable Server-Sent Events with event IDs.
- Search and filter results, inspect raw evidence, export filtered CSV/JSON or a complete scan report.
- SQLite persistence across restarts. Interrupted jobs are marked failed; completed reports remain available.
- Verified, pinned Subfinder, dnsx, ProjectDiscovery httpx, Katana, Nuclei, Naabu and tlsx binaries.
- Domain discovery workflow: Subfinder → dnsx → httpx, with domain-boundary filtering and host limits.
- Docker Compose for the frontend/API, a persistent data volume, and an optional OWASP ZAP baseline worker.

## Quick start with Docker

Install and start Docker Desktop with **Linux containers** (or Docker Engine and
Compose on Linux). From the project root:

```powershell
cd D:\SWOT
docker compose up --build -d
```

- Dashboard: http://localhost:3000
- API health: http://localhost:8000/api/health
- API documentation: http://localhost:8000/docs
- Engine inventory: http://localhost:8000/api/tools

If an existing local server occupies ports 3000/8000, stop it first or copy
`.env.example` to `.env` and choose different `SWOT_WEB_PORT` / `SWOT_API_PORT`.
The browser uses a same-origin `/api` proxy, so changing the web port needs no frontend rebuild.

```powershell
# Include the optional, heavier ZAP worker:
docker compose --profile zap up --build -d

# View status and logs:
docker compose ps
docker compose logs -f backend frontend

# Stop containers; scan history stays in the named volume:
docker compose down
```

Do not use `down -v` unless you intend to delete saved scan data. The ZAP worker's
port and the Docker socket are not exposed. Services bind to loopback by default;
this is a single-user local tool, without an authentication layer. Do not expose
it directly to a public network.

## Local development (Windows)

Python 3.11+ and Node.js 22+ are required. Go is not required.

```powershell
cd D:\SWOT\backend
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In another PowerShell window:

```powershell
cd D:\SWOT\frontend
npm ci
npm run dev
```

Install the seven external engines from the repository root:

```powershell
python scripts/install_tools.py
```

The installer checks the SHA-256 checksum published with each release, installs
into `tools/bin`, and retains bundled license files. Versions are pinned in
`tools/versions.json`; change those pins deliberately before rebuilding.
`httpx` is installed as **pd-httpx** to avoid collisions with the Python HTTP
client's CLI. Built-in scanners work without these binaries. Optional provider
API keys can be configured in Subfinder's generated provider configuration under
`backend/data/tool-state/config`; keys are never required for the whole app.

On Windows, run Uvicorn without `--reload` when using subprocess-based engines;
restart the API after backend edits. Keep one API worker: the live job queue is
process-local. `SWOT_MAX_JOBS` controls concurrency within that worker.

## Scanners and coverage

| Scanner | Coverage |
| --- | --- |
| DNS subdomains | Built-in dictionary-based DNS resolution |
| Ports | Built-in common TCP port checks |
| HTTP fingerprint | Response title, server, header/cookie technology hints and security headers |
| TLS certificate | Certificate fields, names and expiry |
| WHOIS, Wayback | Registration information and archived URLs |
| Directories, API endpoints | Wordlist-based HTTP path discovery |
| WAF | Header and response signatures |
| Technology stack | Server, framework, CMS and JS library/version detection from headers, cookies, markers and asset URLs |
| Admin panel finder | Wordlist-based discovery of administrative/login panels |
| Subdomain takeover | Dangling-CNAME detection against third-party service fingerprints (detection only) |
| Real IP discovery | Candidate origin IPs via Certificate Transparency and CDN-range filtering; optional Shodan/SecurityTrails |
| Dork search | Generates Google/GitHub/Shodan dork URLs; optionally runs them via the Google Programmable Search API |
| Secret exposure | Scans the site's JavaScript for secret patterns; optional GitHub code search |
| Stealer-log exposure | Defensive leak check via LeakCheck / Intelligence X (API key required) |
| Database leak check | Known breaches from the public HIBP catalogue; optional domain-account lookup with a key |
| Subfinder | Passive subdomain enumeration; source coverage depends on provider availability/keys |
| dnsx | A, AAAA and CNAME records |
| httpx | HTTP status, page title, server and technology detection |
| Katana | Same-host crawling, depth 2, up to 60 seconds, JS URL parsing and form extraction |
| Nuclei | Three bundled informational HTTP checks: CSP, nosniff, server version disclosure |
| Naabu | Top 100 TCP ports, CONNECT mode (no raw-socket privileges required) |
| tlsx | TLS and certificate metadata |
| Domain discovery | Subfinder → dnsx → httpx; first 100 discovered hosts by default |
| ZAP baseline | Optional bounded crawl plus passive response analysis; no active attack scan |

The intelligence scanners (real IP, dork search, secret exposure, stealer-log
exposure, database leak) are **key-ready**: they run without credentials and
degrade to a clear "token required" result, and use an optional third-party
provider when its key is set via the `SWOT_*` variables in `.env.example`
(listed under **Tools & engines** as providers). Only official/passive APIs are
used — no HTML scraping and no CAPTCHA handling. Use them only against targets
you are authorized to assess; stealer-log and breach checks are for reviewing
your own exposure.

Nuclei does **not** run the entire community CVE collection by default. The
bundled templates live in `backend/app/templates`, are validated against the
pinned engine, and do not automatically update. Add reviewed templates there
and rebuild to expand coverage. Findings retain template IDs and evidence;
missing headers, HTTP 403, a software banner or an HTTP 200 on a suspicious path
are not automatically labelled confirmed critical vulnerabilities.

External engines use a bounded rate, timeouts and argument-list execution
(without a shell). Cancellation terminates their child process. Discovery
checks domain boundaries and excludes hosts resolving to private/reserved IPs
before HTTP probing. This validation is not network isolation or DNS pinning;
keep the deployment local and restrict targets to your authorized scope.

## Configuration

Copy `.env.example` to `.env` for Compose overrides. For local execution, set
backend variables in its process environment before launching Uvicorn.

| Variable | Default | Purpose |
| --- | --- | --- |
| `SWOT_DATABASE` | `backend/data/swot.db` locally; `/data/swot.db` in Docker | Persistent SQLite database |
| `SWOT_TOOLS_DIR` | `tools/bin` locally | Engine executable directory |
| `SWOT_MAX_JOBS` | `4` | Concurrent scans |
| `SWOT_MAX_QUEUED_JOBS` | `32` | Active + queued job limit |
| `SWOT_SCAN_TIMEOUT` | `300` | Per-job time limit in seconds |
| `SWOT_JOB_TTL` | `900` | In-memory retention; persisted history is retained |
| `SWOT_TOOL_RATE` | `10` | Request/packet rate for supported CLI engines; tlsx uses 2 workers |
| `SWOT_MAX_TOOL_RESULTS` | `1000` | Results per CLI invocation; reaching the cap marks the job incomplete/failed |
| `SWOT_MAX_DISCOVERY_HOSTS` | `100` | Hosts checked in the discovery workflow |
| `SWOT_ALLOWED_DOMAINS` | empty | Optional comma-separated domains; includes their subdomains |
| `SWOT_ZAP_URL` | empty locally | Optional internal ZAP worker URL |
| `SWOT_API_INTERNAL_URL` | `http://127.0.0.1:8000` | Frontend server's API destination; `http://backend:8000` in Compose |
| `SWOT_CORS_ORIGINS` | `http://localhost:3000` | Allowed direct API browser origins |

The old `NEXT_PUBLIC_API_BASE` setting is no longer used. Provider credentials,
engine cache/config, scan databases and downloaded binaries are ignored by Git.
History has no automatic disk-retention policy yet; back up and manage the data
volume according to your needs. Overview and history show the latest 100 scans;
the API supports `limit` (up to 500) and `offset` for older records.

## API

```text
GET  /api/health
GET  /api/tools
GET  /api/scanners
POST /api/scans                 {"scanner":"discovery","target":"example.com"}
GET  /api/scans?limit=100&offset=0
GET  /api/scans/{id}
GET  /api/scans/{id}/events      SSE; supports Last-Event-ID
POST /api/scans/{id}/cancel
```

Unavailable engines return HTTP 503 before a job is created. Unknown scans
return 404, invalid targets return 422, and a full job queue returns 429.

## Validation

```powershell
cd D:\SWOT\backend
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
cd ..\frontend
npm run lint
npm run build
cd ..
docker compose config --quiet
```

Tests cover input validation, persistence and restart recovery, cancellation
before/during execution, SSE replay, slow consumers, subprocess failure and
cleanup, discovery scope, and API contracts. Tests do not scan external targets.

Original project maintained by [@DeathlyHallow5](https://github.com/DeathlyHallow5).
GPL-3.0; third-party engines retain their respective licenses. Use only on systems
you own or are authorized to assess.
