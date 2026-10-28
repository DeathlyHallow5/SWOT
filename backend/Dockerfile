# Build tools separately; only verified release binaries reach the runtime image.
FROM python:3.13-slim-bookworm AS tools
WORKDIR /build
COPY scripts/install_tools.py scripts/install_tools.py
COPY tools/versions.json tools/versions.json
RUN python scripts/install_tools.py --dest /opt/tools

FROM python:3.13-slim-bookworm AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libpcap0.8 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 swot
WORKDIR /app
COPY backend/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=tools /opt/tools /opt/swot-tools
COPY --chown=swot:swot backend/app ./app
RUN mkdir -p /data && chown swot:swot /data
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 SWOT_DATABASE=/data/swot.db SWOT_TOOLS_DIR=/opt/swot-tools
USER swot
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=3)"
# One worker owns the live job queue; SQLite persists scan history.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
