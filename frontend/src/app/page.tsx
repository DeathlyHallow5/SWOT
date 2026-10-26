import ScanConsole from "@/components/ScanConsole";

export default function Home() {
  return (
    <main className="page">
      <header className="masthead">
        <h1>SWOT</h1>
        <p>Smart Website OSINT Tool — authorized reconnaissance only.</p>
      </header>
      <ScanConsole />
    </main>
  );
}
