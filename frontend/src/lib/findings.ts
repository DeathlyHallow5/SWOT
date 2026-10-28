import type { ScanEvent } from "./api";

export interface Column {
  key: string;
  label: string;
  mono?: boolean;
  status?: boolean;
}
export interface Tile {
  num: number | string;
  label: string;
  alert?: boolean;
}
export interface Shape {
  columns: Column[];
  source: string;
}
const host: Column = { key: "host", label: "Host" };
const addresses: Column = { key: "addresses", label: "IP address", mono: true };
const status: Column = { key: "status", label: "Status", status: true };
const TABLE: Record<string, Column[]> = {
  dns_subdomains: [host, addresses],
  subfinder: [host, { key: "sources", label: "Sources" }],
  dnsx: [host, addresses, { key: "cname", label: "CNAME" }],
  httpx: [
    host,
    status,
    { key: "title", label: "Page title" },
    { key: "technologies", label: "Technologies" },
  ],
  discovery: [host, addresses, status, { key: "title", label: "Page title" }],
  naabu: [
    host,
    { key: "port", label: "Port", mono: true },
    { key: "protocol", label: "Protocol" },
  ],
  ports: [
    { key: "port", label: "Port", mono: true },
    { key: "service", label: "Service" },
    { key: "state", label: "State", status: true },
  ],
  directories: [{ key: "path", label: "Path" }, status],
  api_endpoints: [{ key: "path", label: "Path" }, status],
  katana: [
    { key: "url", label: "Endpoint" },
    { key: "method", label: "Method" },
    status,
  ],
  nuclei: [
    { key: "title", label: "Finding" },
    { key: "severity", label: "Severity", status: true },
    { key: "url", label: "Matched URL" },
  ],
  tlsx: [
    host,
    { key: "issuer", label: "Issuer" },
    { key: "expires", label: "Expires" },
  ],
  zap: [
    { key: "title", label: "Finding" },
    { key: "severity", label: "Severity", status: true },
    { key: "url", label: "URL" },
  ],
};
export function shapeFor(scanner: string): Shape {
  return {
    columns: TABLE[scanner] ?? [{ key: "_summary", label: "Observation" }],
    source: scanner,
  };
}
export function display(value: unknown): string {
  if (value === null || value === undefined || value === "") return "—";
  if (Array.isArray(value)) return value.map(display).join(", ") || "—";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}
export function summary(data: Record<string, unknown>): string {
  return String(
    data.title ??
      data.host ??
      data.final_url ??
      data.path ??
      data.url ??
      (data.subject ? display(data.subject) : null) ??
      "View collected evidence",
  );
}
export function tilesFor(scanner: string, findings: ScanEvent[]): Tile[] {
  const data = findings.map((f) => f.data);
  const hosts = new Set(data.map((d) => d.host).filter(Boolean)).size;
  const tech = new Set(
    data.flatMap((d) => (Array.isArray(d.technologies) ? d.technologies : [])),
  ).size;
  if (["discovery", "httpx"].includes(scanner))
    return [
      { num: hosts, label: "Hosts found" },
      {
        num: data.filter((d) => Number(d.status) > 0).length,
        label: "Web responses",
      },
      { num: tech, label: "Technologies" },
    ];
  if (["dns_subdomains", "dnsx", "subfinder"].includes(scanner))
    return [
      { num: hosts, label: "Hosts found" },
      {
        num: new Set(
          data.flatMap((d) => (Array.isArray(d.addresses) ? d.addresses : [])),
        ).size,
        label: "Unique IPs",
      },
      { num: data.length, label: "Observations" },
    ];
  if (["nuclei", "zap"].includes(scanner))
    return [
      { num: data.length, label: "Findings" },
      {
        num: data.filter((d) =>
          ["high", "critical"].includes(String(d.severity)),
        ).length,
        label: "High / critical",
        alert: true,
      },
      {
        num: new Set(data.map((d) => d.template_id ?? d.title)).size,
        label: "Matched checks",
      },
    ];
  if (scanner === "ssl_cert")
    return [
      {
        num:
          data[0]?.days_until_expiry === undefined
            ? "—"
            : Number(data[0].days_until_expiry),
        label: "Days to expiry",
      },
      {
        num: Array.isArray(data[0]?.subject_alt_names)
          ? data[0].subject_alt_names.length
          : 0,
        label: "Certificate names",
      },
    ];
  return [
    { num: data.length, label: "Observations" },
    {
      num: data.filter((d) => Number(d.status) >= 200 && Number(d.status) < 400)
        .length,
      label: "Successful HTTP",
    },
    { num: tech, label: "Technologies" },
  ];
}
export function toCsv(
  columns: Column[],
  source: string,
  findings: ScanEvent[],
): string {
  const rows = findings.map((f) => [
    ...columns.map((c) =>
      c.key === "_summary" ? summary(f.data) : f.data[c.key],
    ),
    f.data.source ?? source,
  ]);
  return [[...columns.map((c) => c.label), "Source"], ...rows]
    .map((row) => row.map(csvCell).join(","))
    .join("\r\n");
}
function csvCell(value: unknown): string {
  let text = value == null ? "" : display(value);
  // Prevent spreadsheet applications from evaluating untrusted scan output.
  if (/^[\s]*[=+@-]/.test(text) || /^[\t\r\n]/.test(text)) text = "'" + text;
  return '"' + text.replace(/"/g, '""') + '"';
}
export function download(name: string, content: string, mime: string) {
  const url = URL.createObjectURL(new Blob([content], { type: mime }));
  const link = document.createElement("a");
  link.href = url;
  link.download = name;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
