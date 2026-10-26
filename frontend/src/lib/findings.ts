// Shapes raw scanner findings into either a table (multi-row scanners) or a
// detail list (single-result scanners), and derives the summary tiles. All
// values come from real scan events — nothing is fabricated.
import type { ScanEvent } from "./api";

export interface Column {
  key: string;
  label: string;
  mono?: boolean;
  status?: boolean; // render value as a coloured status badge
}

export interface Tile {
  num: number;
  label: string;
  alert?: boolean;
}

export interface Shape {
  mode: "table" | "detail";
  columns: Column[];
  source: string; // label for the "Source" column
}

const TABLE: Record<string, Shape> = {
  dns_subdomains: {
    mode: "table",
    source: "DNS",
    columns: [
      { key: "host", label: "Host" },
      { key: "addresses", label: "IP address", mono: true },
    ],
  },
  ports: {
    mode: "table",
    source: "TCP",
    columns: [
      { key: "port", label: "Port", mono: true },
      { key: "service", label: "Service" },
      { key: "state", label: "State", status: true },
    ],
  },
  directories: {
    mode: "table",
    source: "HTTP",
    columns: [
      { key: "path", label: "Path", mono: true },
      { key: "status", label: "Status", status: true },
    ],
  },
  api_endpoints: {
    mode: "table",
    source: "HTTP",
    columns: [
      { key: "path", label: "Path", mono: true },
      { key: "status", label: "Status", status: true },
    ],
  },
};

export function shapeFor(scanner: string): Shape {
  return (
    TABLE[scanner] ?? { mode: "detail", source: scanner, columns: [] }
  );
}

const SENSITIVE = /\.env|\.git|backup|dump|\.sql|wp-config|id_rsa|\.htaccess/i;

// A path finding is "critical" when a sensitive path responds 200.
export function isCritical(scanner: string, data: Record<string, unknown>): boolean {
  if (scanner === "directories" || scanner === "api_endpoints") {
    return data.status === 200 && SENSITIVE.test(String(data.path ?? ""));
  }
  return false;
}

function uniq(values: unknown[]): number {
  return new Set(values.map((v) => JSON.stringify(v))).size;
}

export function tilesFor(
  scanner: string,
  findings: ScanEvent[],
): Tile[] {
  const data = findings.map((f) => f.data);
  const n = data.length;
  const critical = data.filter((d) => isCritical(scanner, d)).length;

  switch (scanner) {
    case "dns_subdomains": {
      const ips = data.flatMap((d) => (d.addresses as string[]) ?? []);
      return [
        { num: n, label: "Subdomains" },
        { num: data.filter((d) => (d.addresses as unknown[])?.length).length, label: "Live hosts" },
        { num: uniq(ips), label: "Unique IPs" },
        { num: 0, label: "Critical issues" },
      ];
    }
    case "ports":
      return [
        { num: n, label: "Open ports" },
        { num: uniq(data.map((d) => d.service)), label: "Services" },
        { num: 0, label: "Critical issues" },
      ];
    case "directories":
    case "api_endpoints": {
      const ok = data.filter((d) => Number(d.status) < 400).length;
      const guarded = data.filter((d) => d.status === 401 || d.status === 403).length;
      return [
        { num: n, label: "Paths found" },
        { num: ok, label: "Accessible" },
        { num: guarded, label: "Protected" },
        { num: critical, label: "Critical issues", alert: critical > 0 },
      ];
    }
    case "wayback":
      return [{ num: Number(data[0]?.count ?? 0), label: "Archived URLs" }];
    case "whois": {
      const ns = (data[0]?.fields as Record<string, unknown>)?.["Name Server"];
      const nsCount = Array.isArray(ns) ? ns.length : ns ? 1 : 0;
      return [{ num: nsCount, label: "Name servers" }];
    }
    case "http_fingerprint": {
      const d = data[0] ?? {};
      const missing = ((d.security_headers_missing as unknown[]) ?? []).length;
      return [
        { num: ((d.technologies as unknown[]) ?? []).length, label: "Technologies" },
        { num: missing, label: "Missing sec headers", alert: missing > 2 },
      ];
    }
    case "waf": {
      const det = (data[0]?.detected as unknown[]) ?? [];
      return [{ num: det.length, label: "WAF/CDN matched" }];
    }
    case "ssl_cert": {
      const d = data[0] ?? {};
      const days = Number(d.days_until_expiry ?? 0);
      return [
        { num: days, label: "Days to expiry", alert: days < 14 },
        { num: ((d.subject_alt_names as unknown[]) ?? []).length, label: "SAN entries" },
      ];
    }
    default:
      return [{ num: n, label: "Findings" }];
  }
}

// Build the CSV for the Export button from a table-shaped scanner.
export function toCsv(columns: Column[], source: string, findings: ScanEvent[]): string {
  const head = [...columns.map((c) => c.label), "Source"].join(",");
  const rows = findings.map((f) =>
    [
      ...columns.map((c) => csvCell(f.data[c.key])),
      source,
    ].join(","),
  );
  return [head, ...rows].join("\n");
}

function csvCell(value: unknown): string {
  const s = Array.isArray(value) ? value.join(" ") : String(value ?? "");
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}
