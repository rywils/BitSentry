import { useEffect, useMemo, useState } from "react";
import type { HistoryFile, HistoryRun, NormalizedFinding, SuiteReport } from "./types";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

function useReportData() {
  const [report, setReport] = useState<SuiteReport | null>(null);
  const [history, setHistory] = useState<HistoryFile | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const load = async () => {
      try {
        const api = await fetch("/api/runs/latest");
        if (api.ok) {
          setReport(await api.json() as SuiteReport);
          const historyResponse = await fetch("/api/runs");
          if (historyResponse.ok) setHistory({ runs: await historyResponse.json() as HistoryRun[] });
          return;
        }
        const local = await fetch("./report.json");
        if (local.ok && (local.headers.get("content-type") || "").includes("json")) setReport(await local.json() as SuiteReport);
      } catch (reason) {
        setError(String(reason));
      }
    };
    load();
  }, []);

  return { report, history, error, reload: () => window.location.reload() };
}

function ScanLauncher({ onComplete }: { onComplete: () => void }) {
  const [target, setTarget] = useState("");
  const [job, setJob] = useState<{ id: string; status: string } | null>(null);
  const [message, setMessage] = useState("");

  useEffect(() => {
    if (!job || ["completed", "failed"].includes(job.status)) return;
    const timer = window.setInterval(async () => {
      const response = await fetch(`/api/scans/${job.id}`);
      if (!response.ok) return;
      const next = await response.json() as { id: string; status: string };
      setJob(next);
      if (next.status === "completed") {
        setMessage("Scan complete");
        onComplete();
      } else if (next.status === "failed") setMessage("Scan failed");
    }, 1500);
    return () => window.clearInterval(timer);
  }, [job, onComplete]);

  const start = async () => {
    setMessage("");
    const response = await fetch("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target }) });
    const contentType = response.headers.get("content-type") || "";
    if (!contentType.includes("application/json")) return setMessage("Start the BitSentry application server to launch scans.");
    const data = await response.json();
    if (!response.ok) return setMessage(data.detail || "Could not start scan");
    setJob(data);
    setTarget("");
  };

  return <div className="scan-launcher">
    <span className="eyebrow">New assessment</span>
    <div className="scan-form">
      <input aria-label="Scan target" value={target} onChange={(event) => setTarget(event.target.value)} placeholder="example.com" disabled={!!job && !["completed", "failed"].includes(job.status)} />
      <button onClick={start} disabled={!target.trim() || (!!job && !["completed", "failed"].includes(job.status))}>Start scan</button>
    </div>
    {job && <span className="scan-status">{job.status} {job.status === "running" ? "· scanning target" : ""}</span>}
    {message && <span className="scan-status">{message}</span>}
  </div>;
}

function historyLabel(run: HistoryRun, index: number) {
  return run.generated_at?.slice(0, 10) || run.run_id?.slice(0, 8) || `run ${index + 1}`;
}

function Header({ report, onScanComplete }: { report?: SuiteReport; onScanComplete: () => void }) {
  return (
    <header className="masthead">
      <div className="brand-lockup">
        <span className="eyebrow">BitSentry / exposure register</span>
        <h1>Know what can break.</h1>
        <p>{report?.target || report?.title || "Local security assessment"}</p>
      </div>
      <div className="run-stamp">
        <span>Latest run</span>
        <strong>{report?.generated_at || "No completed runs"}</strong>
        <code>{report?.run_id?.slice(0, 12) || "ready"}</code>
      </div>
      <ScanLauncher onComplete={onScanComplete} />
    </header>
  );
}

function RiskRail({ report }: { report: SuiteReport }) {
  const stats = report.statistics || {};
  const score = stats.risk?.normalized_score ?? 0;
  const level = stats.risk?.level || "unrated";
  const total = report.rollups?.total_findings ?? stats.total_findings ?? report.findings?.length ?? 0;

  return (
    <section className="risk-rail" aria-label="Risk summary">
      <div className="risk-score">
        <span className="eyebrow">Exposure index</span>
        <strong>{Math.round(score)}</strong>
        <span className={`risk-level level-${level.toLowerCase()}`}>{level}</span>
      </div>
      <div className="rail-stat">
        <span>Grouped findings</span>
        <strong>{total}</strong>
      </div>
      <div className="rail-stat">
        <span>Endpoints in scope</span>
        <strong>{report.findings?.reduce((sum, finding) => sum + (finding.endpoint_count || 1), 0) || 0}</strong>
      </div>
      <div className="rail-note">Counts represent distinct issues, not every page where they appeared.</div>
    </section>
  );
}

function SeveritySummary({ report }: { report: SuiteReport }) {
  const values = report.rollups?.findings_by_severity || {};
  const total = SEVERITIES.reduce((sum, severity) => sum + (values[severity] || 0), 0) || 1;

  return (
    <section className="severity-section">
      <div className="section-heading">
        <span className="eyebrow">Signal / severity</span>
        <h2>Where the exposure concentrates</h2>
      </div>
      <div className="severity-bars">
        {SEVERITIES.map((severity) => {
          const count = values[severity] || 0;
          return (
            <div className={`severity-row severity-${severity}`} key={severity}>
              <span>{severity}</span>
              <div className="severity-track"><i style={{ width: `${(count / total) * 100}%` }} /></div>
              <strong>{count}</strong>
            </div>
          );
        })}
      </div>
    </section>
  );
}

function FindingItem({ finding }: { finding: NormalizedFinding }) {
  const [open, setOpen] = useState(false);
  const severity = (finding.severity || "info").toLowerCase();
  const endpoints = finding.affected_endpoints || (finding.url ? [finding.url] : []);

  return (
    <article className={`finding-item finding-${severity}`}>
      <button className="finding-toggle" onClick={() => setOpen(!open)} aria-expanded={open}>
        <span className="severity-mark" aria-hidden="true" />
        <span className="finding-copy">
          <span className="finding-meta">{severity} / {finding.plugin_name || "scanner"}</span>
          <strong>{finding.title || "Untitled finding"}</strong>
          <span>{finding.description || "No description provided."}</span>
        </span>
        <span className="endpoint-count">{finding.endpoint_count || endpoints.length || 1}<small> endpoints</small></span>
        <span className="chevron" aria-hidden="true">{open ? "−" : "+"}</span>
      </button>
      {open && (
        <div className="finding-detail">
          <div>
            <span className="eyebrow">Remediation</span>
            <p>{finding.remediation || "Review and remediate the affected behavior."}</p>
          </div>
          <div>
            <span className="eyebrow">Affected endpoints</span>
            <ul>{endpoints.map((endpoint) => <li key={endpoint}><code>{endpoint}</code></li>)}</ul>
          </div>
        </div>
      )}
    </article>
  );
}

function FindingsRegister({ findings }: { findings: NormalizedFinding[] }) {
  const [query, setQuery] = useState("");
  const [severity, setSeverity] = useState("all");
  const filtered = useMemo(() => findings.filter((finding) => {
    const text = `${finding.title || ""} ${finding.description || ""} ${finding.plugin_name || ""} ${(finding.affected_endpoints || []).join(" ")}`.toLowerCase();
    return (!query || text.includes(query.toLowerCase())) && (severity === "all" || finding.severity?.toLowerCase() === severity);
  }), [findings, query, severity]);

  return (
    <section className="register">
      <div className="register-header">
        <div className="section-heading"><span className="eyebrow">Findings / grouped</span><h2>Exposure register</h2></div>
        <span className="result-count">{filtered.length} of {findings.length}</span>
      </div>
      <div className="filters">
        <input aria-label="Search findings" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search findings or endpoints" />
        <select aria-label="Filter by severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="all">All severities</option>
          {SEVERITIES.map((item) => <option key={item} value={item}>{item}</option>)}
        </select>
      </div>
      <div className="finding-list">
        {filtered.length ? filtered.map((finding, index) => <FindingItem key={finding.id || `${finding.title}-${index}`} finding={finding} />) : <p className="empty-state">No findings match this filter.</p>}
      </div>
    </section>
  );
}

function History({ history }: { history: HistoryFile }) {
  const runs = history.runs || [];
  return (
    <section className="history">
      <div className="section-heading"><span className="eyebrow">Signal over time</span><h2>Run history</h2></div>
      <div className="history-list">
        {runs.slice(-8).map((run, index) => <div className="history-row" key={run.run_id}><span>{historyLabel(run, index)}</span><i style={{ width: `${Math.min(100, run.weighted_severity_index || 0)}%` }} /><strong>{run.total_findings}</strong></div>)}
      </div>
    </section>
  );
}

function ErrorView({ error }: { error: string }) {
  return <main className="message"><span className="eyebrow">Application error</span><h1>{error}</h1><p>Start the BitSentry web application and try again.</p></main>;
}

export default function App() {
  const { report, history, error, reload } = useReportData();
  if (error) return <ErrorView error={error} />;

  return (
    <div className="app-shell">
      <Header report={report || undefined} onScanComplete={reload} />
      {!report ? <main className="message"><span className="eyebrow">BitSentry</span><h1>Ready for an assessment.</h1><p>Launch a scan above to populate the exposure register.</p></main> : <main>
        <RiskRail report={report} />
        <div className="overview-grid"><SeveritySummary report={report} />{history && <History history={history} />}</div>
        <FindingsRegister findings={report.findings || []} />
      </main>}
      <footer>BitSentry local application <span>·</span> {report?.bitreport_schema_version || "ready"}</footer>
    </div>
  );
}
