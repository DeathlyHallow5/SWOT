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
  tech_stack: [
    { key: "technology", label: "Technology" },
    { key: "version", label: "Version", mono: true },
    { key: "category", label: "Category" },
  ],
  admin_finder: [{ key: "path", label: "Path" }, status],
  subdomain_takeover: [
    host,
    { key: "service", label: "Service" },
    { key: "risk", label: "Risk", status: true },
    { key: "detail", label: "Detail" },
  ],
  real_ip: [
    { key: "ip", label: "IP address", mono: true },
    { key: "classification", label: "Classification" },
    { key: "hosts", label: "Seen on" },
  ],
  dork_search: [
    { key: "category", label: "Category" },
    { key: "query", label: "Query", mono: true },
  ],
  secret_search: [
    { key: "type", label: "Type" },
    { key: "evidence", label: "Evidence", mono: true },
    { key: "location", label: "Location" },
  ],
  stealer_check: [
    { key: "provider", label: "Provider" },
    { key: "username", label: "Account" },
    { key: "sources", label: "Sources" },
    { key: "last_seen", label: "Last seen" },
  ],
  db_leak: [
    { key: "breach", label: "Breach" },
    { key: "breach_date", label: "Date" },
    { key: "pwned_accounts", label: "Accounts", mono: true },
    { key: "data_classes", label: "Exposed data" },
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
      data.technology ??
      data.breach ??
      data.ip ??
      data.type ??
      data.service ??
      data.host ??
      data.final_url ??
      data.path ??
      data.url ??
      data.category ??
      data.provider ??
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
  if (scanner === "tech_stack")
    return [
      { num: data.length, label: "Technologies" },
      { num: data.filter((d) => d.version).length, label: "With version" },
      {
        num: new Set(data.map((d) => d.category).filter(Boolean)).size,
        label: "Categories",
      },
    ];
  if (scanner === "subdomain_takeover")
    return [
      { num: data.length, label: "At-risk hosts" },
      {
        num: data.filter((d) => d.risk === "high").length,
        label: "High risk",
        alert: true,
      },
    ];
  if (scanner === "admin_finder")
    return [
      { num: data.length, label: "Panels found" },
      {
        num: data.filter((d) => Number(d.status) < 400).length,
        label: "Accessible",
      },
      {
        num: data.filter((d) => [401, 403].includes(Number(d.status))).length,
        label: "Protected",
      },
    ];
  if (scanner === "real_ip")
    return [
      {
        num: data.filter((d) =>
          String(d.classification).includes("origin"),
        ).length,
        label: "Candidate origins",
      },
      {
        num: new Set(data.map((d) => d.ip).filter(Boolean)).size,
        label: "Unique IPs",
      },
    ];
  if (scanner === "dork_search")
    return [{ num: data.length, label: "Dork queries" }];
  if (scanner === "secret_search")
    return [
      {
        num: data.filter((d) => d.status !== "token_required" && d.type).length,
        label: "Potential secrets",
        alert: true,
      },
      {
        num: data.filter((d) => d.source === "github").length,
        label: "Code matches",
      },
    ];
  if (scanner === "stealer_check")
    return [
      {
        num: data.filter((d) => d.status !== "token_required" && d.provider)
          .length,
        label: "Leak records",
        alert: true,
      },
    ];
  if (scanner === "db_leak")
    return [
      {
        num: data.filter((d) => d.breach).length,
        label: "Known breaches",
        alert: true,
      },
      {
        num: data.reduce((n, d) => n + (Number(d.pwned_accounts) || 0), 0),
        label: "Pwned accounts",
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
