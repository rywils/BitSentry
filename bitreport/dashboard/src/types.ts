export type HistoryRun = {
  run_id: string;
  generated_at: string;
  primary_target?: string;
  total_findings: number;
  weighted_severity_index: number;
  run_dir?: string;
};

export type HistoryFile = {
  schema?: string;
  runs: HistoryRun[];
  updated_at?: string;
};

export type SuiteReport = {
  bitreport_schema_version?: string;
  suite?: string;
  report_type?: string;
  title?: string;
  run_id?: string;
  generated_at?: string;
  target?: string;
  sources?: {
    bitprobe?: { included?: boolean; scans?: unknown[] };
    bitscope?: { included?: boolean; summary?: Record<string, unknown> };
  };
  rollups?: {
    total_findings?: number;
    findings_by_severity?: Record<string, number>;
    findings_by_plugin?: Record<string, number>;
  };
  statistics?: {
    total_findings?: number;
    risk?: { normalized_score?: number; level?: string };
  };
  findings?: NormalizedFinding[];
};

export type NormalizedFinding = {
  id?: string;
  source_product?: string;
  severity?: string;
  title?: string;
  url?: string;
  plugin_name?: string;
  description?: string;
  remediation?: string;
  evidence?: Record<string, unknown>;
  endpoint_count?: number;
  affected_endpoints?: string[];
  risk_score?: number;
};
