// Thin client for the SWOT API. Scans are started with POST, then followed
// live over Server-Sent Events.

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE ?? "http://localhost:8000";

export interface ScannerInfo {
  name: string;
  title: string;
  description: string;
}

export interface ScanEvent {
  seq: number;
  kind: "log" | "finding" | "progress" | "status";
  data: Record<string, unknown>;
  at: number;
}

export interface ScanAccepted {
  job_id: string;
  scanner: string;
  target: string;
}

export async function fetchScanners(): Promise<ScannerInfo[]> {
  const res = await fetch(`${API_BASE}/api/scanners`, { cache: "no-store" });
  if (!res.ok) throw new Error(`failed to load scanners (${res.status})`);
  return res.json();
}

export async function startScan(
  scanner: string,
  target: string,
): Promise<ScanAccepted> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scanner, target }),
  });
  if (res.status === 422 || res.status === 404) {
    const body = (await res.json().catch(() => ({}))) as { detail?: string };
    throw new Error(body.detail ?? "invalid request");
  }
  if (!res.ok) throw new Error(`failed to start scan (${res.status})`);
  return res.json();
}

export async function cancelScan(jobId: string): Promise<void> {
  await fetch(`${API_BASE}/api/scans/${jobId}/cancel`, { method: "POST" });
}

// Open an SSE stream for a job. Returns an unsubscribe function.
export function streamScan(
  jobId: string,
  handlers: {
    onEvent: (event: ScanEvent) => void;
    onEnd: (status: string, error: string | null) => void;
    onError: () => void;
  },
): () => void {
  const source = new EventSource(`${API_BASE}/api/scans/${jobId}/events`);

  source.addEventListener("event", (e) => {
    handlers.onEvent(JSON.parse((e as MessageEvent).data) as ScanEvent);
  });
  source.addEventListener("end", (e) => {
    const payload = JSON.parse((e as MessageEvent).data) as {
      status: string;
      error: string | null;
    };
    handlers.onEnd(payload.status, payload.error);
    source.close();
  });
  source.onerror = () => {
    handlers.onError();
    source.close();
  };

  return () => source.close();
}
