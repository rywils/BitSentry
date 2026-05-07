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
  sources?: {
    bitprobe?: { included?: boolean; scans?: unknown[] };
    bitscope?: { included?: boolean; summary?: Record<string, unknown> };
  };
  rollups?: {
    total_findings?: number;
    findings_by_severity?: Record<string, number>;
    findings_by_plugin?: Record<string, number>;
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
  risk_score?: number;
};
