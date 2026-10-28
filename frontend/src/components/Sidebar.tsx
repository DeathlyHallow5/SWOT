import { IcClock, IcGrid, IcSearch, IcSettings, IcExternal } from "./icons";

export type View = "overview" | "scans" | "history" | "tools";
const items = [
  { id: "overview", label: "Overview", Icon: IcGrid },
  { id: "scans", label: "Scans", Icon: IcSearch },
  { id: "history", label: "Scan history", Icon: IcClock },
  { id: "tools", label: "Tools & engines", Icon: IcSettings },
] as const;

export default function Sidebar({
  view,
  onChange,
  running,
}: {
  view: View;
  onChange: (view: View) => void;
  running: boolean;
}) {
  return (
    <aside className="sidebar">
      <button
        className="brand"
        onClick={() => onChange("overview")}
        aria-label="SWOT overview"
      >
        <span className="brand-mark" aria-hidden="true">
          <i />
          <i />
          <i />
          <i />
          <i />
        </span>
        SWOT <span className="version">2.1</span>
      </button>
      <div className="nav-label">WORKSPACE</div>
      <nav className="nav" aria-label="Main navigation">
        {items.map(({ id, label, Icon }) => (
          <button
            key={id}
            className={view === id ? "active" : ""}
            aria-current={view === id ? "page" : undefined}
            onClick={() => onChange(id)}
          >
            <Icon />
            {label}
            {id === "scans" && running && <span className="dot pulse" />}
          </button>
        ))}
      </nav>
      <div className="sidebar-foot">
        <div className="workspace-label">
          <span className="workspace-avatar">L</span>
          <div>
            Local workspace<small>Your reconnaissance console</small>
          </div>
        </div>
        <a
          className="docs-link"
          href="https://docs.projectdiscovery.io/opensource"
          target="_blank"
          rel="noreferrer"
        >
          Engine documentation <IcExternal width={14} height={14} />
        </a>
      </div>
    </aside>
  );
}
