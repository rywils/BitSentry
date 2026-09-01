import { useEffect, useMemo, useState } from "react";
import type { HistoryFile, HistoryRun, NormalizedFinding, SuiteReport } from "./types";

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

function useJson<T>(path: string) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(path)
      .then((response) => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json() as Promise<T>;
      })
      .then(setData)
      .catch((reason) => setError(String(reason)));
  }, [path]);

  return { data, error };
}

function historyLabel(run: HistoryRun, index: number) {
  return run.generated_at?.slice(0, 10) || run.run_id?.slice(0, 8) || `run ${index + 1}`;
}

function Header({ report }: { report: SuiteReport }) {
  return (
    <header className="masthead">
      <div className="brand-lockup">
        <span className="eyebrow">BitSentry / exposure register</span>
        <h1>Know what can break.</h1>
        <p>{report.target || report.title || "Security assessment"}</p>
      </div>
      <div className="run-stamp">
        <span>Latest run</span>
        <strong>{report.generated_at || "—"}</strong>
        <code>{report.run_id?.slice(0, 12) || "unidentified"}</code>
      </div>
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
  return <main className="message"><span className="eyebrow">Report unavailable</span><h1>{error}</h1><p>Serve this directory over HTTP so the dashboard can read report.json.</p></main>;
}

export default function App() {
  const report = useJson<SuiteReport>("./report.json");
  const history = useJson<HistoryFile>("./history.json");
  if (report.error) return <ErrorView error={report.error} />;
  if (!report.data) return <main className="message"><span className="eyebrow">BitSentry</span><h1>Reading the register.</h1></main>;

  return (
    <div className="app-shell">
      <Header report={report.data} />
      <main>
        <RiskRail report={report.data} />
        <div className="overview-grid"><SeveritySummary report={report.data} />{history.data && <History history={history.data} />}</div>
        <FindingsRegister findings={report.data.findings || []} />
      </main>
      <footer>Generated by BitSentry <span>·</span> {report.data.bitreport_schema_version || "report schema"}</footer>
    </div>
  );
}
