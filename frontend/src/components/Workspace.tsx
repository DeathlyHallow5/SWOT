"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import Sidebar, { type View } from "./Sidebar";
import {
  IcAlert,
  IcArrow,
  IcCalendar,
  IcCheck,
  IcClock,
  IcDownload,
  IcExternal,
  IcSearch,
  IcShield,
  IcSettings,
} from "./icons";
import {
  cancelScan,
  fetchHealth,
  fetchHistory,
  fetchNucleiOptions,
  fetchScan,
  fetchScanners,
  fetchTools,
  startScan,
  streamScan,
  type NucleiOptions,
  type RunState,
  type ScanDetail,
  type ScanEvent,
  type ScannerInfo,
  type ScanSummary,
  type ToolInfo,
} from "@/lib/api";
import {
  display,
  download,
  shapeFor,
  summary,
  tilesFor,
  toCsv,
} from "@/lib/findings";

const headings: Record<View, [string, string]> = {
  scans: [
    "Scan workspace",
    "Discover and inspect your external attack surface.",
  ],
  overview: [
    "Workspace overview",
    "Your investigations, findings and tools in one place.",
  ],
  history: ["Scan history", "Revisit results and export your investigations."],
  tools: [
    "Tools & engines",
    "Purpose-built scanners. One connected workspace.",
  ],
};
const isActive = (status?: string) =>
  status === "running" || status === "queued";
const date = (at: number) =>
  new Date(at * 1000).toLocaleString("en-GB", {
    day: "2-digit",
    month: "short",
    hour: "2-digit",
    minute: "2-digit",
  });

export default function Workspace() {
  const [view, setView] = useState<View>("scans");
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [tools, setTools] = useState<ToolInfo[]>([]);
  const [history, setHistory] = useState<ScanSummary[]>([]);
  const [scanner, setScanner] = useState("dns_subdomains");
  const [target, setTarget] = useState("");
  const [nuclei, setNuclei] = useState<NucleiOptions | null>(null);
  const [nucleiSource, setNucleiSource] = useState("bundled");
  const [nucleiProfile, setNucleiProfile] = useState("safe");
  const [job, setJob] = useState<ScanDetail | null>(null);
  const [online, setOnline] = useState<boolean | null>(null);
  const [connected, setConnected] = useState(true);
  const [pending, setPending] = useState(false);
  const [cancelling, setCancelling] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [tab, setTab] = useState("findings");
  const [selected, setSelected] = useState<ScanEvent | null>(null);
  const [now, setNow] = useState(0);
  const stopRef = useRef<(() => void) | null>(null);
  const generation = useRef(0);
  const catalogLoaded = useRef(false);
  const busy = pending || isActive(job?.status);

  const refresh = useCallback(async () => {
    const [catalog, runs, engines] = await Promise.all([
      fetchScanners(),
      fetchHistory(),
      fetchTools(),
    ]);
    setScanners(catalog);
    setHistory(runs);
    setTools(engines);
    setOnline(true);
    catalogLoaded.current = true;
  }, []);

  const follow = useCallback(
    (id: string) => {
      stopRef.current?.();
      const token = ++generation.current;
      stopRef.current = streamScan(id, {
        onEvent: (event) => {
          if (generation.current !== token) return;
          setJob((prev) => {
            if (
              !prev ||
              prev.job_id !== id ||
              prev.events.some((e) => e.seq === event.seq)
            )
              return prev;
            const status =
              event.kind === "status"
                ? (event.data.status as RunState)
                : prev.status;
            return {
              ...prev,
              status,
              finding_count:
                prev.finding_count + (event.kind === "finding" ? 1 : 0),
              finished_at:
                event.kind === "status" && !isActive(status)
                  ? event.at
                  : prev.finished_at,
              events: [...prev.events, event],
            };
          });
        },
        onConnection: (value) => {
          if (generation.current === token) setConnected(value);
        },
        onEnd: (status, error) => {
          if (generation.current !== token) return;
          setConnected(true);
          setCancelling(false);
          setJob((prev) =>
            prev?.job_id === id
              ? {
                  ...prev,
                  status,
                  error,
                  finished_at: prev.finished_at ?? Date.now() / 1000,
                }
              : prev,
          );
          if (error) setMessage(error);
          refresh().catch(() => setOnline(false));
        },
      });
    },
    [refresh],
  );

  useEffect(() => {
    let disposed = false;
    Promise.all([fetchScanners(), fetchHistory(), fetchTools()])
      .then(([catalog, runs, engines]) => {
        if (disposed) return;
        setScanners(catalog);
        setHistory(runs);
        setTools(engines);
        setOnline(true);
        catalogLoaded.current = true;
      })
      .catch((err: Error) => {
        if (!disposed) {
          setOnline(false);
          setMessage(err.message);
        }
      });
    const saved = localStorage.getItem("swot.lastScan");
    if (saved && /^[a-f0-9]{32}$/.test(saved)) {
      fetchScan(saved)
        .then((detail) => {
          if (disposed) return;
          setJob(detail);
          setTarget(detail.target);
          setScanner(detail.scanner);
          if (isActive(detail.status)) follow(detail.job_id);
        })
        .catch(() => localStorage.removeItem("swot.lastScan"));
    }
    const timer = setInterval(() => {
      fetchHealth()
        .then(() => {
          setOnline(true);
          if (!catalogLoaded.current) return refresh();
        })
        .catch(() => setOnline(false));
    }, 15000);
    return () => {
      disposed = true;
      stopRef.current?.();
      clearInterval(timer);
    };
  }, [refresh, follow]);

  useEffect(() => {
    if (!busy) return;
    const timer = setInterval(() => setNow(Date.now() / 1000), 1000);
    return () => clearInterval(timer);
  }, [busy]);

  useEffect(() => {
    if (scanner !== "nuclei" || nuclei) return;
    fetchNucleiOptions()
      .then(setNuclei)
      .catch(() => setNuclei(null));
  }, [scanner, nuclei]);

  const findings = useMemo(
    () => job?.events.filter((e) => e.kind === "finding") ?? [],
    [job],
  );
  const activity = useMemo(
    () => job?.events.filter((e) => e.kind !== "finding").slice(-150) ?? [],
    [job],
  );
  const technologies = useMemo(
    () => [
      ...new Set(
        findings.flatMap((e) =>
          Array.isArray(e.data.technologies)
            ? e.data.technologies.map(String)
            : [],
        ),
      ),
    ],
    [findings],
  );
  const filtered = useMemo(
    () =>
      findings.filter((e) => {
        const matchesQuery = JSON.stringify(e.data)
          .toLowerCase()
          .includes(query.toLowerCase());
        const code = Number(e.data.status);
        const matchesStatus =
          statusFilter === "all" ||
          (statusFilter === "success" && code >= 200 && code < 400) ||
          (statusFilter === "restricted" && [401, 403].includes(code)) ||
          (statusFilter === "risk" &&
            ["high", "critical"].includes(String(e.data.severity)));
        return matchesQuery && matchesStatus;
      }),
    [findings, query, statusFilter],
  );
  const shape = shapeFor(job?.scanner ?? "dns_subdomains");
  const tiles = job
    ? tilesFor(job.scanner, findings)
    : [
        { num: "—", label: "Hosts found" },
        { num: "—", label: "Web responses" },
        { num: "—", label: "Technologies" },
      ];
  const selectedScanner = scanners.find((s) => s.name === scanner);
  const progress = job?.events.findLast((e) => e.kind === "progress");
  const elapsed = job
    ? Math.max(
        0,
        Math.round(
          (job.finished_at ?? (now || job.created_at)) - job.created_at,
        ),
      )
    : 0;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (busy || !target.trim() || !selectedScanner?.available) return;
    setPending(true);
    setMessage(null);
    setQuery("");
    setStatusFilter("all");
    setTab("findings");
    try {
      const options =
        scanner === "nuclei"
          ? { source: nucleiSource, profile: nucleiProfile }
          : undefined;
      const { job_id } = await startScan(scanner, target.trim(), options);
      const detail = await fetchScan(job_id);
      setJob(detail);
      setNow(Date.now() / 1000);
      setConnected(true);
      localStorage.setItem("swot.lastScan", job_id);
      if (isActive(detail.status)) follow(job_id);
      await refresh();
    } catch (error) {
      setMessage((error as Error).message);
    } finally {
      setPending(false);
    }
  }
  async function openScan(id: string) {
    if (busy && id !== job?.job_id) {
      setMessage(
        "Finish or cancel the current scan before opening another one.",
      );
      return;
    }
    try {
      const detail = await fetchScan(id);
      stopRef.current?.();
      generation.current++;
      setJob(detail);
      setTarget(detail.target);
      setScanner(detail.scanner);
      setView("scans");
      setQuery("");
      setStatusFilter("all");
      setMessage(detail.error);
      setConnected(true);
      localStorage.setItem("swot.lastScan", id);
      if (isActive(detail.status)) follow(id);
    } catch (error) {
      setMessage((error as Error).message);
    }
  }
  async function cancel() {
    if (!job) return;
    setCancelling(true);
    try {
      await cancelScan(job.job_id);
    } catch (error) {
      setMessage((error as Error).message);
      setCancelling(false);
    }
  }
  function exportResults(format: "csv" | "json") {
    if (!job) return;
    const body =
      format === "csv"
        ? toCsv(shape.columns, shape.source, filtered)
        : JSON.stringify(
            {
              ...job,
              finding_count: filtered.length,
              total_finding_count: findings.length,
              export_scope: "filtered_findings",
              events: filtered,
            },
            null,
            2,
          );
    download(
      `swot-${job.scanner}-${job.job_id.slice(0, 8)}.${format}`,
      body,
      format === "csv" ? "text/csv;charset=utf-8" : "application/json",
    );
  }
  async function exportRun(id: string) {
    try {
      const detail = await fetchScan(id);
      download(
        `swot-${id.slice(0, 8)}.json`,
        JSON.stringify(detail, null, 2),
        "application/json",
      );
    } catch (error) {
      setMessage((error as Error).message);
    }
  }
  function choose(name: string) {
    if (!busy) {
      setScanner(name);
      setView("scans");
      setMessage(null);
    }
  }

  return (
    <div className="shell">
      <Sidebar
        view={view}
        onChange={(v) => {
          setView(v);
          setQuery("");
        }}
        running={busy}
      />
      <main className="main">
        <div className="breadcrumb">
          Workspace <span>/</span>{" "}
          {view === "tools"
            ? "Engines"
            : view === "history"
              ? "History"
              : view === "overview"
                ? "Overview"
                : "Scans"}
        </div>
        <header className="main-head">
          <div>
            <h1>{headings[view][0]}</h1>
            <p>{headings[view][1]}</p>
          </div>
          <span
            className={`pill ${online === false ? "offline" : ""}`}
            role="status"
          >
            <span className="dot" />
            {online === null
              ? "Connecting to API"
              : online
                ? "API connected"
                : "API offline"}
          </span>
        </header>
        {message && (
          <div className="notice" role="alert">
            <IcAlert width={18} height={18} />
            <span>{message}</span>
            <button
              onClick={() => setMessage(null)}
              aria-label="Dismiss message"
            >
              ×
            </button>
          </div>
        )}

        {view === "scans" && (
          <>
            <form className="card newscan" onSubmit={submit}>
              <div className="section-heading">
                <span className="card-label">NEW SCAN</span>
                <span className="tiny muted">01 / CONFIGURE TARGET</span>
              </div>
              <div className="scan-row">
                <label className="field scanner-field">
                  <span>Scan type</span>
                  <select
                    aria-label="Scanner"
                    value={scanner}
                    onChange={(e) => setScanner(e.target.value)}
                    disabled={busy}
                  >
                    {!scanners.length && (
                      <option value="dns_subdomains">Loading scanners…</option>
                    )}
                    {["workflow", "builtin", "intel", "external"].map((category) => (
                      <optgroup
                        key={category}
                        label={
                          category === "workflow"
                            ? "Workflows"
                            : category === "builtin"
                              ? "Built-in scanners"
                              : category === "intel"
                                ? "Intelligence (API)"
                                : "External engines"
                        }
                      >
                        {scanners
                          .filter((s) => s.category === category)
                          .map((s) => (
                            <option
                              key={s.name}
                              value={s.name}
                              disabled={!s.available}
                            >
                              {s.title}
                              {!s.available ? " · not installed" : ""}
                            </option>
                          ))}
                      </optgroup>
                    ))}
                  </select>
                </label>
                <label className="field target-field">
                  <span>Target domain or URL</span>
                  <input
                    aria-label="Target"
                    placeholder="example.com"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    disabled={busy}
                    required
                    maxLength={255}
                    autoComplete="off"
                    spellCheck={false}
                  />
                </label>
                {busy ? (
                  <button
                    type="button"
                    className="btn btn-danger"
                    onClick={cancel}
                    disabled={pending || cancelling}
                  >
                    {pending
                      ? "Starting…"
                      : cancelling
                        ? "Cancelling…"
                        : "Cancel scan"}
                  </button>
                ) : (
                  <button
                    className="btn"
                    type="submit"
                    disabled={
                      !target.trim() || !selectedScanner?.available || !online
                    }
                  >
                    Start scan <IcArrow width={18} height={18} />
                  </button>
                )}
              </div>
              {scanner === "nuclei" && (
                <div className="scan-row nuclei-row">
                  <label className="field">
                    <span>Template source</span>
                    <select
                      aria-label="Nuclei template source"
                      value={nucleiSource}
                      onChange={(e) => setNucleiSource(e.target.value)}
                      disabled={busy}
                    >
                      {(nuclei?.sources ?? []).map((s) => (
                        <option
                          key={s.id}
                          value={s.id}
                          disabled={s.available === false}
                        >
                          {s.title}
                          {s.available === false ? " · not installed" : ""}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="field">
                    <span>Scan profile</span>
                    <select
                      aria-label="Nuclei scan profile"
                      value={nucleiProfile}
                      onChange={(e) => setNucleiProfile(e.target.value)}
                      disabled={busy}
                    >
                      {(nuclei?.profiles ?? []).map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.title}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
              )}
              <div className="scan-caption">
                <span>
                  {selectedScanner?.description ??
                    "Choose a scanner to start your investigation."}
                </span>
                <span>
                  <IcShield width={14} height={14} /> Authorized targets only
                </span>
              </div>
            </form>
            <section className="card summary-card" aria-label="Scan summary">
              <div className="summary-id">
                <div className="summary-target">
                  <h2>{job?.target ?? "Ready to explore"}</h2>
                  {job ? (
                    <StatusBadge status={job.status} />
                  ) : (
                    <span className="badge neutral">Idle</span>
                  )}
                </div>
                <div className="summary-meta">
                  <span>
                    <IcCalendar width={14} height={14} />
                    {job ? date(job.created_at) : "No scan selected"}
                  </span>
                  <span>
                    <IcClock width={14} height={14} />
                    {job ? `${elapsed}s` : "—"}
                  </span>
                </div>
              </div>
              <div className="tiles">
                {tiles.map((tile) => (
                  <div className="tile" key={tile.label}>
                    <strong
                      className={
                        tile.alert && Number(tile.num) > 0 ? "danger-text" : ""
                      }
                    >
                      {tile.num}
                    </strong>
                    <span>{tile.label}</span>
                  </div>
                ))}
              </div>
            </section>
            {busy && (
              <div className="progress-line" role="status">
                <span className="dot pulse" />
                {job?.status === "queued"
                  ? "Waiting for an available worker"
                  : String(progress?.data.stage ?? "Scan in progress")}
                {progress && (
                  <span>
                    {String(progress.data.done)} / {String(progress.data.total)}
                  </span>
                )}
                {!connected && (
                  <span className="warning-text">
                    Reconnecting to live results…
                  </span>
                )}
              </div>
            )}
            <div className="content">
              <section className="card results-card">
                <div className="tabs" role="tablist" aria-label="Scan results">
                  <button
                    role="tab"
                    aria-selected={tab === "findings"}
                    className={tab === "findings" ? "active" : ""}
                    onClick={() => setTab("findings")}
                  >
                    Findings{" "}
                    <span className="count-chip">{findings.length}</span>
                  </button>
                  <button
                    role="tab"
                    aria-selected={tab === "technologies"}
                    className={tab === "technologies" ? "active" : ""}
                    onClick={() => setTab("technologies")}
                  >
                    Technologies{" "}
                    <span className="count-chip">{technologies.length}</span>
                  </button>
                </div>
                {tab === "findings" ? (
                  <>
                    <div className="toolbar">
                      <label className="search">
                        <IcSearch width={17} height={17} />
                        <input
                          aria-label="Search findings"
                          placeholder="Search hosts, IPs or values…"
                          value={query}
                          onChange={(e) => setQuery(e.target.value)}
                        />
                      </label>
                      <select
                        className="compact-select"
                        aria-label="Filter findings"
                        value={statusFilter}
                        onChange={(e) => setStatusFilter(e.target.value)}
                      >
                        <option value="all">All results</option>
                        <option value="success">HTTP 2xx / 3xx</option>
                        <option value="restricted">HTTP 401 / 403</option>
                        <option value="risk">High / critical</option>
                      </select>
                    </div>
                    <div className="table-wrap">
                      <table className="findings">
                        <thead>
                          <tr>
                            {shape.columns.map((c) => (
                              <th key={c.key}>{c.label}</th>
                            ))}
                            <th>Source</th>
                            <th>
                              <span className="sr-only">Details</span>
                            </th>
                          </tr>
                        </thead>
                        <tbody>
                          {filtered.map((row) => (
                            <tr key={row.seq}>
                              {shape.columns.map((c) => (
                                <td
                                  key={c.key}
                                  className={c.mono ? "mono" : ""}
                                >
                                  {c.status ? (
                                    <ValueBadge value={row.data[c.key]} />
                                  ) : (
                                    <span
                                      className="cell-text"
                                      title={display(row.data[c.key])}
                                    >
                                      {c.key === "_summary"
                                        ? summary(row.data)
                                        : display(row.data[c.key])}
                                    </span>
                                  )}
                                </td>
                              ))}
                              <td className="muted">
                                {display(row.data.source ?? shape.source)}
                              </td>
                              <td>
                                <button
                                  className="icon-button"
                                  aria-label={`Details for ${summary(row.data)}`}
                                  onClick={() => setSelected(row)}
                                >
                                  <IcExternal width={16} height={16} />
                                </button>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                    {!filtered.length && (
                      <Empty
                        title={
                          !job
                            ? "Your next discovery starts here"
                            : findings.length
                              ? "No matching findings"
                              : busy
                                ? "Looking for signals…"
                                : "No findings returned"
                        }
                        text={
                          !job
                            ? "Enter a target above. Findings will appear here as they arrive."
                            : findings.length
                              ? "Try another search or filter."
                              : busy
                                ? "Results stream live from the selected scanner."
                                : "Review the activity log for scan coverage and errors."
                        }
                      />
                    )}
                    <div className="results-foot">
                      <span>
                        {filtered.length} of {findings.length} observations
                      </span>
                      <div>
                        <button
                          className="text-button"
                          disabled={!filtered.length}
                          onClick={() => exportResults("csv")}
                        >
                          <IcDownload width={14} height={14} />
                          CSV
                        </button>
                        <button
                          className="text-button"
                          disabled={!filtered.length}
                          onClick={() => exportResults("json")}
                        >
                          JSON
                        </button>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="technology-list">
                    {technologies.length ? (
                      technologies.map((tech) => (
                        <div className="technology" key={tech}>
                          <span className="tech-icon">
                            {tech.slice(0, 1).toUpperCase()}
                          </span>
                          <div>
                            {tech}
                            <small>Detected in scan responses</small>
                          </div>
                        </div>
                      ))
                    ) : (
                      <Empty
                        title="No technologies detected"
                        text="Run HTTP Fingerprint, httpx or the discovery workflow to identify technologies."
                      />
                    )}
                  </div>
                )}
              </section>
              <aside className="card activity">
                <div className="section-heading">
                  <h2>Activity log</h2>
                  <span className="tiny muted">{busy ? "LIVE" : "EVENTS"}</span>
                </div>
                <div className="log-list" aria-label="Scan activity">
                  {activity.map((event) => (
                    <LogLine key={event.seq} event={event} />
                  ))}
                  {!activity.length && (
                    <div className="log-placeholder">
                      <span className="terminal-symbol">&gt;_</span>
                      <p>Standing by</p>
                      <small>Scan activity will appear here.</small>
                    </div>
                  )}
                </div>
              </aside>
            </div>
          </>
        )}

        {view === "overview" && (
          <>
            <div className="overview-tiles">
              {[
                { num: history.length, label: "Recent scans" },
                {
                  num: history.filter((s) => s.status === "done").length,
                  label: "Completed",
                },
                {
                  num: history.reduce((n, s) => n + s.finding_count, 0),
                  label: "Saved observations",
                },
                {
                  num: scanners.filter((s) => s.available).length,
                  label: "Available scanners",
                },
              ].map((t) => (
                <div className="card overview-tile" key={t.label}>
                  <span>{t.label}</span>
                  <strong>{t.num}</strong>
                </div>
              ))}
            </div>
            <div className="section-heading spaced">
              <h2>Start an investigation</h2>
              <span className="muted tiny">CHOOSE YOUR WORKFLOW</span>
            </div>
            <div className="quick-grid">
              {[
                {
                  name: "discovery",
                  title: "Map a domain",
                  text: "Discover subdomains, resolve DNS and identify web services.",
                  tag: "SUBFINDER → DNSX → HTTPX",
                },
                {
                  name: "http_fingerprint",
                  title: "Inspect a website",
                  text: "Identify technologies, response headers and page information.",
                  tag: "BUILT-IN · NO INSTALL REQUIRED",
                },
                {
                  name: "nuclei",
                  title: "Check configuration",
                  text: "Run the bundled, read-only HTTP configuration checks.",
                  tag: "NUCLEI · CURATED TEMPLATES",
                },
              ].map((item) => (
                <button
                  className="card quick-card"
                  key={item.name}
                  onClick={() => choose(item.name)}
                  disabled={busy}
                >
                  <IcSearch width={22} height={22} />
                  <h3>{item.title}</h3>
                  <p>{item.text}</p>
                  <span>
                    {item.tag} <IcArrow width={16} height={16} />
                  </span>
                </button>
              ))}
            </div>
            <div className="section-heading spaced">
              <h2>Recent activity</h2>
              <button
                className="text-button"
                onClick={() => setView("history")}
              >
                View history <IcArrow width={16} height={16} />
              </button>
            </div>
            <HistoryTable
              rows={history.slice(0, 5)}
              open={openScan}
              exportRun={exportRun}
            />
          </>
        )}
        {view === "history" && (
          <>
            <div className="history-toolbar">
              <label className="search">
                <IcSearch width={17} height={17} />
                <input
                  aria-label="Search scan history"
                  placeholder="Search by target or scanner…"
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                />
              </label>
              <button
                className="btn btn-ghost"
                onClick={() => refresh().catch((e) => setMessage(e.message))}
              >
                Refresh
              </button>
            </div>
            <HistoryTable
              rows={history.filter((s) =>
                `${s.target} ${s.scanner}`
                  .toLowerCase()
                  .includes(query.toLowerCase()),
              )}
              open={openScan}
              exportRun={exportRun}
            />
            <p className="muted tiny">
              Latest 100 scans · Saved locally in your workspace database
            </p>
          </>
        )}
        {view === "tools" && (
          <>
            <div className="tools-intro card">
              <IcSettings width={24} height={24} />
              <div>
                <h2>Your scanning toolkit</h2>
                <p>
                  Built-in scanners are always available. The Docker image
                  includes all seven ProjectDiscovery engines. ZAP is an
                  optional Compose profile.
                </p>
              </div>
              <button
                className="btn btn-ghost"
                onClick={() => refresh().catch((e) => setMessage(e.message))}
              >
                Refresh status
              </button>
            </div>
            <div className="tools-grid">
              {tools.map((tool) => (
                <article className="card tool-card" key={tool.name}>
                  <div className="section-heading">
                    <span className="tool-name">{tool.title}</span>
                    <span
                      className={`badge ${tool.available ? "success" : "neutral"}`}
                    >
                      {tool.available ? "Ready" : "Not installed"}
                    </span>
                  </div>
                  <p>{tool.description}</p>
                  <div className="tool-meta">
                    <span className="mono tiny">
                      {tool.version ??
                        (tool.available ? "Available" : "Enable in Docker")}
                    </span>
                    <a
                      className="text-button"
                      href={tool.docs}
                      target="_blank"
                      rel="noreferrer"
                    >
                      Docs <IcExternal width={13} height={13} />
                    </a>
                  </div>
                  {tool.name.startsWith("provider:") ? (
                    <span className="tiny muted">
                      {tool.available
                        ? "Key configured · used by intel scanners"
                        : "Add an API key to enable intel scanners"}
                    </span>
                  ) : (
                    <button
                      className="btn btn-ghost"
                      disabled={!tool.available || busy}
                      onClick={() => choose(tool.name)}
                    >
                      Use {tool.title}
                      <IcArrow width={14} height={14} />
                    </button>
                  )}
                </article>
              ))}
            </div>
          </>
        )}
        <footer className="foot">
          <span>
            <span className="dot" /> Local workspace
          </span>
          <span>
            SWOT <span className="muted">/</span> Smart Website OSINT Tool
          </span>
        </footer>
      </main>
      {selected && (
        <FindingDialog event={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}

function Empty({ title, text }: { title: string; text: string }) {
  return (
    <div className="empty">
      <div className="radar" aria-hidden="true">
        <div />
        <IcSearch width={24} height={24} />
      </div>
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}
function StatusBadge({ status }: { status: RunState }) {
  return (
    <span
      className={`badge ${status === "done" ? "success" : status === "error" ? "danger" : isActive(status) ? "warning" : "neutral"}`}
    >
      {status === "done" ? (
        <IcCheck width={13} height={13} />
      ) : isActive(status) ? (
        <span className="dot pulse" />
      ) : null}
      {
        {
          done: "Completed",
          running: "Scanning",
          queued: "Queued",
          cancelled: "Cancelled",
          error: "Failed",
        }[status]
      }
    </span>
  );
}
function ValueBadge({ value }: { value: unknown }) {
  if (value === undefined || value === null)
    return <span className="muted">—</span>;
  const n = Number(value);
  const color =
    ["critical", "high"].includes(String(value)) || n >= 500
      ? "danger"
      : n >= 400 || value === "medium"
        ? "warning"
        : (n >= 200 && n < 300) || value === "open"
          ? "success"
          : "neutral";
  return <span className={`value-badge ${color}`}>{String(value)}</span>;
}
function LogLine({ event }: { event: ScanEvent }) {
  const level = String(event.data.level ?? "info");
  const text =
    event.kind === "status"
      ? `Scan ${event.data.status}`
      : event.kind === "progress"
        ? `${event.data.stage ?? "Progress"}: ${event.data.done}/${event.data.total}`
        : String(event.data.message ?? "");
  return (
    <div className="log-item">
      <time>{new Date(event.at * 1000).toLocaleTimeString("en-GB")}</time>
      {level === "error" || level === "warn" ? (
        <IcAlert
          className={level === "error" ? "danger-text" : "warning-text"}
          width={15}
          height={15}
        />
      ) : (
        <IcCheck width={15} height={15} />
      )}
      <span>{text}</span>
    </div>
  );
}
function HistoryTable({
  rows,
  open,
  exportRun,
}: {
  rows: ScanSummary[];
  open: (id: string) => void;
  exportRun: (id: string) => void;
}) {
  return (
    <section className="card results-card">
      <div className="table-wrap">
        <table className="findings history-table">
          <thead>
            <tr>
              <th>Target</th>
              <th>Scanner</th>
              <th>Status</th>
              <th>Findings</th>
              <th>Started</th>
              <th>Report</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((run) => (
              <tr key={run.job_id}>
                <td>
                  <button
                    className="target-link"
                    onClick={() => open(run.job_id)}
                  >
                    {run.target}
                  </button>
                </td>
                <td className="muted">{run.scanner.replace(/_/g, " ")}</td>
                <td>
                  <StatusBadge status={run.status} />
                </td>
                <td className="mono">{run.finding_count}</td>
                <td className="muted">{date(run.created_at)}</td>
                <td>
                  <button
                    className="icon-button"
                    aria-label={`Export scan ${run.job_id}`}
                    onClick={() => exportRun(run.job_id)}
                  >
                    <IcDownload width={17} height={17} />
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!rows.length && (
        <Empty
          title="A clean slate"
          text="Your saved scans will appear here. Start an investigation to build your history."
        />
      )}
    </section>
  );
}
function FindingDialog({
  event,
  onClose,
}: {
  event: ScanEvent;
  onClose: () => void;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    dialog?.showModal();
    return () => dialog?.close();
  }, []);
  return (
    <dialog
      className="finding-dialog"
      ref={ref}
      onClose={onClose}
      aria-labelledby="finding-title"
    >
      <div className="section-heading">
        <div>
          <span className="card-label">FINDING DETAILS</span>
          <h2 id="finding-title">{summary(event.data)}</h2>
        </div>
        <button
          className="icon-button close-button"
          aria-label="Close finding"
          onClick={onClose}
        >
          ×
        </button>
      </div>
      <p className="muted tiny">
        Observed {date(event.at)} · Event #{event.seq}
      </p>
      <dl className="detail">
        {Object.entries(event.data).map(([key, value]) => (
          <div key={key}>
            <dt>{key.replace(/_/g, " ")}</dt>
            <dd>
              {typeof value === "object" && value !== null ? (
                <pre>{JSON.stringify(value, null, 2)}</pre>
              ) : (
                display(value)
              )}
            </dd>
          </div>
        ))}
      </dl>
      <button
        className="btn btn-ghost"
        onClick={() =>
          download(
            `swot-finding-${event.seq}.json`,
            JSON.stringify(event.data, null, 2),
            "application/json",
          )
        }
      >
        <IcDownload width={16} height={16} />
        Export evidence
      </button>
    </dialog>
  );
}
