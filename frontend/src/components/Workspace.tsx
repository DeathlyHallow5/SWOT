"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  cancelScan,
  fetchScanners,
  startScan,
  streamScan,
  type ScanEvent,
  type ScannerInfo,
} from "@/lib/api";
import {
  shapeFor,
  tilesFor,
  toCsv,
  type Column,
} from "@/lib/findings";
import {
  IcAlert,
  IcArrow,
  IcCalendar,
  IcCheck,
  IcClock,
  IcDownload,
  IcSearch,
  IcShield,
  IcExternal,
} from "./icons";

type RunState = "idle" | "running" | "done" | "error" | "cancelled";

function hhmmss(epoch: number): string {
  return new Date(epoch * 1000).toLocaleTimeString("en-GB", { hour12: false });
}

function statusClass(value: unknown): string {
  if (value === "open") return "s-2";
  const n = Number(value);
  if (n >= 200 && n < 300) return "s-2";
  if (n >= 300 && n < 400) return "s-3";
  return "s-4";
}

export default function Workspace() {
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [scanner, setScanner] = useState("");
  const [target, setTarget] = useState("");
  const [state, setState] = useState<RunState>("idle");
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [message, setMessage] = useState<string | null>(null);
  const [ran, setRan] = useState<{ scanner: string; target: string } | null>(null);
  const [startedAt, setStartedAt] = useState(0);
  const [finishedAt, setFinishedAt] = useState(0);
  const [query, setQuery] = useState("");
  const jobRef = useRef<string | null>(null);
  const stopRef = useRef<(() => void) | null>(null);

  useEffect(() => {
    fetchScanners()
      .then((list) => {
        setScanners(list);
        if (list[0]) setScanner(list[0].name);
      })
      .catch((e: Error) => setMessage(e.message));
    return () => stopRef.current?.();
  }, []);

  const findings = useMemo(() => events.filter((e) => e.kind === "finding"), [events]);
  const activity = useMemo(
    () => events.filter((e) => e.kind !== "finding"),
    [events],
  );

  const shape = ran ? shapeFor(ran.scanner) : null;
  const tiles = ran ? tilesFor(ran.scanner, findings) : [];
  const title = scanners.find((s) => s.name === scanner)?.title ?? "";

  const filtered = useMemo(() => {
    if (!query.trim()) return findings;
    const q = query.toLowerCase();
    return findings.filter((f) => JSON.stringify(f.data).toLowerCase().includes(q));
  }, [findings, query]);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!scanner || !target.trim() || state === "running") return;
    setEvents([]);
    setMessage(null);
    setQuery("");
    setState("running");
    setRan({ scanner, target: target.trim() });
    setStartedAt(Date.now() / 1000);
    setFinishedAt(0);
    try {
      const { job_id } = await startScan(scanner, target.trim());
      jobRef.current = job_id;
      stopRef.current = streamScan(job_id, {
        onEvent: (ev) => setEvents((prev) => [...prev, ev]),
        onEnd: (status, error) => {
          setState(status as RunState);
          setFinishedAt(Date.now() / 1000);
          if (error) setMessage(error);
        },
        onError: () => {
          setState("error");
          setMessage("lost connection to the scan stream");
        },
      });
    } catch (err) {
      setState("error");
      setMessage((err as Error).message);
    }
  }

  async function onCancel() {
    if (jobRef.current) await cancelScan(jobRef.current);
  }

  function onExport() {
    if (!ran || !shape) return;
    const isTable = shape.mode === "table";
    const body = isTable
      ? toCsv(shape.columns, shape.source, findings)
      : JSON.stringify(findings.map((f) => f.data), null, 2);
    const blob = new Blob([body], {
      type: isTable ? "text/csv" : "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `swot-${ran.scanner}-${ran.target}.${isTable ? "csv" : "json"}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const duration = finishedAt && startedAt ? Math.max(1, Math.round(finishedAt - startedAt)) : null;

  return (
    <>
      <div className="main-head">
        <div>
          <h1>Scan workspace</h1>
          <p>Discover and inspect your external attack surface.</p>
        </div>
        <span className="pill">
          <span className="dot" /> All systems operational
        </span>
      </div>

      {/* New scan */}
      <form className="card newscan" onSubmit={onSubmit}>
        <div className="card-label">NEW SCAN</div>
        <div className="scan-row">
          <select
            className="select"
            aria-label="Scanner"
            value={scanner}
            onChange={(e) => setScanner(e.target.value)}
            disabled={state === "running"}
          >
            {scanners.map((s) => (
              <option key={s.name} value={s.name}>
                {s.title}
              </option>
            ))}
          </select>
          <input
            className="input"
            aria-label="Target"
            placeholder="example.com"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            disabled={state === "running"}
          />
          {state === "running" ? (
            <button type="button" className="btn btn-danger" onClick={onCancel}>
              Cancel
            </button>
          ) : (
            <button type="submit" className="btn">
              Start scan <IcArrow width={16} height={16} />
            </button>
          )}
        </div>
        <div className="note">
          <IcShield width={15} height={15} />
          Authorized reconnaissance only. Ensure you have permission to scan the
          target.
        </div>
      </form>

      {!ran ? (
        <div className="card empty">
          Run a scan to see findings, metrics and the activity log here.
        </div>
      ) : (
        <>
          {/* Summary */}
          <div className="card summary">
            <div className="summary-id">
              <div className="summary-target">
                {ran.target}
                <StatusBadge state={state} />
              </div>
              <div className="summary-meta">
                <span>
                  <IcCalendar width={14} height={14} />
                  {new Date(startedAt * 1000).toLocaleString("en-GB", {
                    day: "2-digit",
                    month: "short",
                    year: "numeric",
                    hour: "2-digit",
                    minute: "2-digit",
                  })}
                </span>
                <span>
                  <IcClock width={14} height={14} />
                  {duration ? `${duration}s` : state === "running" ? "running…" : "—"}
                </span>
                <span>{title}</span>
              </div>
            </div>
            <div className="tiles">
              {tiles.map((t) => (
                <div className="tile" key={t.label}>
                  <div className={`tile-num${t.alert ? " alert" : ""}`}>{t.num}</div>
                  <div className="tile-label">{t.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* Content: findings + activity */}
          <div className="content">
            <div className="card">
              <div className="tabs">
                <span className="tab active">
                  Findings <span className="count-chip">{findings.length}</span>
                </span>
              </div>

              <div className="toolbar">
                <label className="search">
                  <IcSearch />
                  <input
                    placeholder="Search hosts, IPs or values…"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                  />
                </label>
                <button
                  className="btn btn-ghost"
                  onClick={onExport}
                  disabled={findings.length === 0}
                >
                  <IcDownload width={15} height={15} /> Export
                </button>
              </div>

              {shape?.mode === "table" ? (
                <FindingsTable columns={shape.columns} source={shape.source} rows={filtered} />
              ) : (
                <FindingsDetail rows={filtered} />
              )}
            </div>

            <div className="card activity">
              <div className="card-label">ACTIVITY LOG</div>
              <div className="log-list">
                {activity.map((e) => (
                  <LogLine key={e.seq} event={e} />
                ))}
                {activity.length === 0 && <div className="empty">Waiting…</div>}
              </div>
            </div>
          </div>

          <div className="foot">
            <span>{findings.length} findings discovered</span>
            <span>SWOT — Smart Website OSINT Tool</span>
          </div>
        </>
      )}
    </>
  );
}

function StatusBadge({ state }: { state: RunState }) {
  if (state === "running")
    return <span className="badge badge-run"><Spinner /> Scanning</span>;
  if (state === "done")
    return <span className="badge badge-ok"><IcCheck width={13} height={13} /> Completed</span>;
  if (state === "cancelled")
    return <span className="badge badge-run">Cancelled</span>;
  return <span className="badge badge-err"><IcAlert width={13} height={13} /> Error</span>;
}

function Spinner() {
  return (
    <svg className="spin" width={13} height={13} viewBox="0 0 24 24" fill="none"
      stroke="currentColor" strokeWidth={3} strokeLinecap="round">
      <path d="M12 3a9 9 0 1 0 9 9" />
    </svg>
  );
}

function FindingsTable({
  columns,
  source,
  rows,
}: {
  columns: Column[];
  source: string;
  rows: ScanEvent[];
}) {
  if (rows.length === 0) return <div className="empty">No findings yet.</div>;
  return (
    <table className="findings">
      <thead>
        <tr>
          {columns.map((c) => (
            <th key={c.key}>{c.label}</th>
          ))}
          <th>Source</th>
          <th />
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.seq}>
            {columns.map((c) => (
              <td key={c.key} className={c.mono && !c.status ? "mono" : undefined}>
                {c.status ? (
                  <span className={`status-badge ${statusClass(r.data[c.key])}`}>
                    {String(r.data[c.key])}
                  </span>
                ) : (
                  cell(r.data[c.key])
                )}
              </td>
            ))}
            <td className="mono">{source}</td>
            <td>
              <a className="row-link" title="raw finding">
                <IcExternal width={15} height={15} />
              </a>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function cell(value: unknown): string {
  if (Array.isArray(value)) return value.join(", ");
  return String(value ?? "—");
}

function FindingsDetail({ rows }: { rows: ScanEvent[] }) {
  if (rows.length === 0) return <div className="empty">No findings yet.</div>;
  return (
    <>
      {rows.map((r) => (
        <dl className="detail" key={r.seq}>
          {Object.entries(r.data).map(([k, v]) => (
            <div className="detail-row" key={k}>
              <dt>{k.replace(/_/g, " ")}</dt>
              <dd>{renderValue(v)}</dd>
            </div>
          ))}
        </dl>
      ))}
    </>
  );
}

function renderValue(v: unknown) {
  if (Array.isArray(v)) {
    if (v.length === 0) return <span className="mono">—</span>;
    return (
      <div className="chips">
        {v.map((item, i) => (
          <span className="chip" key={i}>
            {String(item)}
          </span>
        ))}
      </div>
    );
  }
  if (v && typeof v === "object") {
    return (
      <div className="chips">
        {Object.entries(v as Record<string, unknown>).map(([k, val]) => (
          <span className="chip" key={k}>
            {k}: {Array.isArray(val) ? val.join(" · ") : String(val)}
          </span>
        ))}
      </div>
    );
  }
  return <span>{String(v ?? "—")}</span>;
}

function LogLine({ event }: { event: ScanEvent }) {
  const level = String(event.data.level ?? "info");
  let msg: string;
  if (event.kind === "progress") msg = `progress ${event.data.done}/${event.data.total}`;
  else if (event.kind === "status") msg = `scan ${event.data.status}`;
  else msg = String(event.data.message ?? "");
  return (
    <div className="log-item">
      <span className="log-time">{hhmmss(event.at)}</span>
      <IcCheck className={`log-ic ${level}`} />
      <span className="log-msg">{msg}</span>
    </div>
  );
}
