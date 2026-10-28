# SWOT frontend

Next.js dashboard for SWOT. See the repository root README for setup and Docker.

```powershell
npm ci
npm run dev
```

The browser calls same-origin `/api` routes. Set `SWOT_API_INTERNAL_URL` in the
Next.js server environment if the FastAPI service is not at `http://127.0.0.1:8000`.
There are no build-time remote font downloads and no frontend API credentials.

```powershell
npm run lint
npm run build
```

The Dockerfile deploys Next.js standalone output as a non-root user.
