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

type RunState = "idle" | "running" | "done" | "error" | "cancelled";

export default function ScanConsole() {
  const [scanners, setScanners] = useState<ScannerInfo[]>([]);
  const [scanner, setScanner] = useState("");
  const [target, setTarget] = useState("");
  const [state, setState] = useState<RunState>("idle");
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [message, setMessage] = useState<string | null>(null);
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

  const findings = useMemo(
    () => events.filter((e) => e.kind === "finding"),
    [events],
  );
  const logs = useMemo(
    () => events.filter((e) => e.kind === "log" || e.kind === "progress"),
    [events],
  );

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!scanner || !target.trim() || state === "running") return;
    setEvents([]);
    setMessage(null);
    setState("running");
    try {
      const { job_id } = await startScan(scanner, target.trim());
      jobRef.current = job_id;
      stopRef.current = streamScan(job_id, {
        onEvent: (ev) => setEvents((prev) => [...prev, ev]),
        onEnd: (status, error) => {
          setState(status as RunState);
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

  return (
    <section className="console">
      <form className="controls" onSubmit={onSubmit}>
        <select
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
          aria-label="Target"
          placeholder="example.com"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          disabled={state === "running"}
        />
        {state === "running" ? (
          <button type="button" onClick={onCancel} className="danger">
            Cancel
          </button>
        ) : (
          <button type="submit">Start scan</button>
        )}
      </form>

      <p className={`status status-${state}`}>
        {state === "running" ? "scanning…" : state}
        {message ? ` — ${message}` : ""}
      </p>

      <div className="panes">
        <div className="pane">
          <h2>Findings ({findings.length})</h2>
          {findings.length === 0 ? (
            <p className="muted">No findings yet.</p>
          ) : (
            <ul className="findings">
              {findings.map((f) => (
                <li key={f.seq}>
                  <pre>{JSON.stringify(f.data, null, 2)}</pre>
                </li>
              ))}
            </ul>
          )}
        </div>
        <div className="pane">
          <h2>Log</h2>
          <ul className="log">
            {logs.map((l) => (
              <li key={l.seq} className={`lvl-${String(l.data.level ?? "info")}`}>
                {l.kind === "progress"
                  ? `progress ${l.data.done}/${l.data.total}`
                  : String(l.data.message ?? "")}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}
