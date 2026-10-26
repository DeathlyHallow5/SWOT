import {
  IcDb,
  IcGrid,
  IcReport,
  IcSearch,
  IcSettings,
  IcShield,
} from "./icons";

// Scans is the working view today; the other entries are placeholders for
// where Overview / Assets / Reports will live.
export default function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="brand">
        <span className="brand-mark">
          <IcShield width={26} height={26} />
        </span>
        SWOT
      </div>

      <div className="nav-label">WORKSPACE</div>
      <nav className="nav">
        <a>
          <IcGrid />
          Overview
        </a>
        <a className="active">
          <IcSearch />
          Scans
        </a>
        <a>
          <IcDb />
          Assets
        </a>
        <a>
          <IcReport />
          Reports
        </a>
      </nav>

      <div className="sidebar-foot">
        <nav className="nav">
          <a>
            <IcSettings />
            Settings
          </a>
        </nav>
      </div>
    </aside>
  );
}
