// All browser traffic uses the runtime proxy; container hostnames stay server-side.
export const API_BASE = "";

export type RunState = "queued" | "running" | "done" | "error" | "cancelled";
export interface ScannerInfo {
  name: string;
  title: string;
  description: string;
  available: boolean;
  category: string;
  requires: string[];
}
export interface ToolInfo {
  name: string;
  title: string;
  description: string;
  available: boolean;
  version: string | null;
  docs: string;
}
export interface ScanEvent {
  seq: number;
  kind: "log" | "finding" | "progress" | "status";
  data: Record<string, unknown>;
  at: number;
}
export interface ScanSummary {
  job_id: string;
  scanner: string;
  target: string;
  status: RunState;
  created_at: number;
  finished_at: number | null;
  error: string | null;
  finding_count: number;
}
export interface ScanDetail extends ScanSummary {
  events: ScanEvent[];
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${API_BASE}/api${path}`, {
    cache: "no-store",
    ...init,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    const detail = body.detail;
    throw new Error(
      typeof detail === "string" ? detail : `Request failed (${res.status})`,
    );
  }
  return res.json() as Promise<T>;
}
export const fetchScanners = () => request<ScannerInfo[]>("/scanners");
export const fetchTools = () => request<ToolInfo[]>("/tools");
export const fetchHistory = () => request<ScanSummary[]>("/scans?limit=100");
export const fetchScan = (id: string) =>
  request<ScanDetail>(`/scans/${encodeURIComponent(id)}`);
export const fetchHealth = () => request<{ status: string }>("/health");
export const cancelScan = (id: string) =>
  request(`/scans/${encodeURIComponent(id)}/cancel`, { method: "POST" });
export const startScan = (scanner: string, target: string) =>
  request<{ job_id: string }>("/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scanner, target }),
  });

// EventSource reconnects automatically. The server resumes using Last-Event-ID.
export function streamScan(
  id: string,
  handlers: {
    onEvent: (event: ScanEvent) => void;
    onEnd: (status: RunState, error: string | null) => void;
    onConnection: (connected: boolean) => void;
  },
): () => void {
  const source = new EventSource(
    `${API_BASE}/api/scans/${encodeURIComponent(id)}/events`,
  );
  source.onopen = () => handlers.onConnection(true);
  source.addEventListener("event", (e) =>
    handlers.onEvent(JSON.parse((e as MessageEvent).data)),
  );
  source.addEventListener("end", (e) => {
    const payload = JSON.parse((e as MessageEvent).data);
    source.close();
    handlers.onEnd(payload.status, payload.error);
  });
  source.onerror = () => handlers.onConnection(false);
  return () => source.close();
}
