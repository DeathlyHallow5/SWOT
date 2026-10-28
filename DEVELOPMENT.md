# Development stages — 2026-10-27

## 1. Dashboard — implemented and checked
- Responsive dark dashboard, scan controls, live results, filters, finding details.
- History, restore after reload, CSV/JSON exports, actual engine status.
- Browser checks used a separate synthetic fixture database, not external targets.
- ESLint and production build pass.

## 2. Engines and persistence — implemented and checked
- SQLite scan/event history, SSE replay, cancellation and queue handling.
- Subfinder, dnsx, httpx, Katana, Nuclei, Naabu, tlsx; discovery workflow.
- Shared version probes with update checks disabled; duplicate observations removed.
- 40 backend tests pass. All seven installed CLI version probes pass.
- Actual httpx, Katana, Nuclei and Naabu checked against a local HTTP fixture.
- Nuclei defaults to three bundled informational HTTP checks, not a full CVE suite.

## 3. Docker — configuration prepared, runtime verification pending
- Backend/frontend Dockerfiles, persistent volume, optional ZAP worker.
- Compose configuration validates with the ZAP profile.
- Docker Engine is absent on this machine; images have not been built or run.

## Apply latest code locally
Stop existing backend with Ctrl+C, then in PowerShell:

```powershell
cd D:\SWOT\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

In a second PowerShell terminal:

```powershell
cd D:\SWOT\frontend
npm run dev -- --hostname 127.0.0.1 --port 3000
```

The agent stopped its previous frontend processes before the successful build.
Automatic approval policy blocked its subsequent background launch.
No commits or pushes were made.
