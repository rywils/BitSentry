import type { CSSProperties } from "react";
import { useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { HistoryFile, NormalizedFinding, SuiteReport } from "./types";

const SEV_COLORS: Record<string, string> = {
  critical: "#f85149",
  high: "#db6d28",
  medium: "#d4a72c",
  low: "#3fb950",
  info: "#58a6ff",
};

function useReport() {
  const [data, setData] = useState<SuiteReport | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    fetch("./report.json")
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.json();
      })
      .then((j) => setData(j as SuiteReport))
      .catch((e) => setErr(String(e)));
  }, []);

  return { data, err };
}

function useHistory() {
  const [hist, setHist] = useState<HistoryFile | null>(null);
  useEffect(() => {
    fetch("./history.json")
      .then((r) => (r.ok ? r.json() : null))
      .then((j) => (j && Array.isArray(j.runs) ? setHist(j as HistoryFile) : setHist(null)))
      .catch(() => setHist(null));
  }, []);
  return hist;
}

export default function App() {
  const { data, err } = useReport();
  const hist = useHistory();
  const [q, setQ] = useState("");
  const [sev, setSev] = useState<string | "all">("all");

  const findings = data?.findings ?? [];

  const sevData = useMemo(() => {
    const m = data?.rollups?.findings_by_severity ?? {};
    return Object.entries(m)
      .filter(([, v]) => (v as number) > 0)
      .map(([name, value]) => ({ name, value: value as number }));
  }, [data]);

  const pluginData = useMemo(() => {
    const m = data?.rollups?.findings_by_plugin ?? {};
    return Object.entries(m)
      .map(([name, value]) => ({ name, value: value as number }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 14);
  }, [data]);

  const historyTrend = useMemo(() => {
    const runs = hist?.runs ?? [];
    if (!runs.length) return [];
    return runs.map((r, i) => ({
      label:
        r.generated_at?.slice(0, 10) ||
        r.run_id?.slice(0, 8) ||
        `#${i + 1}`,
      findings: r.total_findings ?? 0,
      riskIndex: r.weighted_severity_index ?? 0,
    }));
  }, [hist]);

  const filtered = useMemo(() => {
    let rows = findings;
    const s = q.trim().toLowerCase();
    if (s) {
      rows = rows.filter((f) => {
        const t = `${f.title ?? ""} ${f.url ?? ""} ${f.plugin_name ?? ""}`.toLowerCase();
        return t.includes(s);
      });
    }
    if (sev !== "all") {
      rows = rows.filter((f) => (f.severity ?? "").toLowerCase() === sev);
    }
    return rows;
  }, [findings, q, sev]);

  if (err) {
    return (
      <div style={shell}>
        <header style={header}>
          <h1 style={{ margin: 0, fontSize: "1.35rem", fontWeight: 600 }}>BitReport</h1>
        </header>
        <main style={{ padding: "2rem", maxWidth: 720 }}>
          <p style={{ color: "var(--crit)" }}>
            Could not load <code>report.json</code>: {err}
          </p>
          <p style={{ color: "var(--muted)", fontSize: "0.9rem" }}>
            Serve this folder over HTTP (e.g. <code>python -m http.server 8765</code>) so the
            dashboard can fetch the report. Opening <code>index.html</code> via{" "}
            <code>file://</code> often blocks fetch.
          </p>
        </main>
      </div>
    );
  }

  if (!data) {
    return (
      <div style={shell}>
        <header style={header}>
          <h1 style={{ margin: 0, fontSize: "1.35rem" }}>BitReport</h1>
        </header>
        <main style={{ padding: "3rem", color: "var(--muted)" }}>Loading report…</main>
      </div>
    );
  }

  return (
    <div style={shell}>
      <header style={header}>
        <div>
          <h1 style={{ margin: 0, fontSize: "1.35rem", fontWeight: 600 }}>BitReport</h1>
          <p style={{ margin: "0.35rem 0 0", color: "var(--muted)", fontSize: "0.88rem" }}>
            {data.title ?? "Suite report"} · {data.generated_at ?? ""}
          </p>
        </div>
        <div
          style={{
            textAlign: "right",
            fontSize: "0.8rem",
            color: "var(--muted)",
            fontFamily: '"IBM Plex Mono", monospace',
          }}
        >
          run {data.run_id?.slice(0, 8)}…
        </div>
      </header>

      <main style={{ padding: "1.25rem 1.5rem 3rem", maxWidth: 1280, margin: "0 auto" }}>
        <section style={grid2}>
          <div style={panel}>
            <h2 style={h2}>Findings by severity</h2>
            <div style={{ width: "100%", height: 280 }}>
              <ResponsiveContainer>
                <PieChart>
                  <Pie
                    data={sevData}
                    dataKey="value"
                    nameKey="name"
                    innerRadius={48}
                    outerRadius={88}
                    paddingAngle={2}
                  >
                    {sevData.map((e) => (
                      <Cell key={e.name} fill={SEV_COLORS[e.name] ?? "#6e7681"} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div style={panel}>
            <h2 style={h2}>Top plugins (BitProbe)</h2>
            <div style={{ width: "100%", height: 280 }}>
              <ResponsiveContainer>
                <BarChart data={pluginData} layout="vertical" margin={{ left: 8, right: 16 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis type="number" stroke="#8b8f9a" />
                  <YAxis type="category" dataKey="name" width={120} stroke="#8b8f9a" tick={{ fontSize: 11 }} />
                  <Tooltip />
                  <Bar dataKey="value" fill="var(--accent)" radius={[0, 4, 4, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
        </section>

        {historyTrend.length > 0 ? (
          <section style={{ ...panel, marginTop: "1.25rem" }}>
            <h2 style={h2}>Suite run history ({historyTrend.length} runs)</h2>
            <p style={{ color: "var(--muted)", fontSize: "0.85rem", marginTop: 0 }}>
              Aggregated across prior BitReport builds under the same --suite-out tree. Current run is
              included after the latest full-scan.
            </p>
            <div style={{ width: "100%", height: 300 }}>
              <ResponsiveContainer>
                <LineChart data={historyTrend} margin={{ left: 8, right: 12 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                  <XAxis dataKey="label" stroke="#8b8f9a" tick={{ fontSize: 11 }} />
                  <YAxis
                    yAxisId="left"
                    stroke="#58a6ff"
                    tick={{ fontSize: 11 }}
                    label={{ value: "Findings", angle: -90, position: "insideLeft", fill: "#58a6ff" }}
                  />
                  <YAxis
                    yAxisId="right"
                    orientation="right"
                    stroke="#d4a72c"
                    tick={{ fontSize: 11 }}
                    label={{
                      value: "Weighted severity index",
                      angle: 90,
                      position: "insideRight",
                      fill: "#d4a72c",
                    }}
                  />
                  <Tooltip />
                  <Legend />
                  <Line
                    yAxisId="left"
                    type="monotone"
                    dataKey="findings"
                    name="Total findings"
                    stroke="#58a6ff"
                    strokeWidth={2}
                    dot={{ r: 3 }}
                  />
                  <Line
                    yAxisId="right"
                    type="monotone"
                    dataKey="riskIndex"
                    name="Severity index"
                    stroke="#d4a72c"
                    strokeWidth={2}
                    dot={{ r: 3 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </section>
        ) : null}

        <section style={{ ...panel, marginTop: "1.25rem" }}>
          <div
            style={{
              display: "flex",
              flexWrap: "wrap",
              gap: "0.75rem",
              alignItems: "center",
              marginBottom: "1rem",
            }}
          >
            <h2 style={{ ...h2, margin: 0, flex: "1 1 200px" }}>All findings</h2>
            <input
              type="search"
              placeholder="Filter title / URL / plugin…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
              style={input}
            />
            <select value={sev} onChange={(e) => setSev(e.target.value as typeof sev)} style={input}>
              <option value="all">All severities</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
              <option value="info">info</option>
            </select>
            <span style={{ color: "var(--muted)", fontSize: "0.85rem" }}>
              {filtered.length} / {findings.length}
            </span>
          </div>
          <div style={{ overflowX: "auto" }}>
            <table style={table}>
              <thead>
                <tr>
                  <th>Sev</th>
                  <th>Plugin</th>
                  <th>Title</th>
                  <th>URL / asset</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((f: NormalizedFinding, i: number) => (
                  <tr key={f.id ?? i}>
                    <td>
                      <span
                        style={{
                          ...badge,
                          background:
                            SEV_COLORS[(f.severity ?? "info").toLowerCase()] ?? "#6e7681",
                        }}
                      >
                        {(f.severity ?? "—").toUpperCase()}
                      </span>
                    </td>
                    <td style={{ fontFamily: '"IBM Plex Mono", monospace', fontSize: "0.78rem" }}>
                      {f.plugin_name ?? "—"}
                    </td>
                    <td>{f.title ?? "—"}</td>
                    <td style={{ wordBreak: "break-all", fontSize: "0.85rem", color: "var(--muted)" }}>
                      {f.url ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  );
}

const shell: CSSProperties = { minHeight: "100vh", background: "var(--bg)" };
const header: CSSProperties = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "flex-start",
  padding: "1.25rem 1.5rem",
  borderBottom: "1px solid var(--border)",
  background: "linear-gradient(180deg, #111218 0%, var(--bg) 100%)",
};
const panel: CSSProperties = {
  background: "var(--panel)",
  border: "1px solid var(--border)",
  borderRadius: 10,
  padding: "1rem 1.1rem",
};
const grid2: CSSProperties = {
  display: "grid",
  gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 340px), 1fr))",
  gap: "1.25rem",
};
const h2: CSSProperties = {
  margin: "0 0 0.75rem",
  fontSize: "1rem",
  fontWeight: 600,
  color: "var(--text)",
};
const input: CSSProperties = {
  background: "#0c0d10",
  border: "1px solid var(--border)",
  color: "var(--text)",
  borderRadius: 6,
  padding: "0.45rem 0.65rem",
  minWidth: 200,
  fontSize: "0.88rem",
};
const table: CSSProperties = {
  width: "100%",
  borderCollapse: "collapse",
  fontSize: "0.88rem",
};
const badge: CSSProperties = {
  display: "inline-block",
  padding: "0.12rem 0.4rem",
  borderRadius: 4,
  fontSize: "0.65rem",
  fontWeight: 600,
  color: "#0c0d10",
};
