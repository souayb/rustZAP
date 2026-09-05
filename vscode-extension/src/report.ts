/** JSON report shapes from rustzap (see src/report.rs, src/types.rs). */

export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface CodeLocation {
  file: string;
  line_start: number;
  line_end?: number | null;
}

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  url: string;
  parameter?: string | null;
  evidence?: string | null;
  description: string;
  solution: string;
  cwe?: number | null;
  owasp_category?: string | null;
  plugin: string;
  source_tool?: string | null;
  location?: CodeLocation | null;
  correlated_with?: string[];
  poc_validated?: boolean;
  confidence?: "tentative" | "firm" | "confirmed";
  found_at?: string;
}

export interface ModuleSummary {
  name: string;
  findings: number;
  max_severity: Severity | null;
  quiet: boolean;
}

export interface ReportSummary {
  total_findings: number;
  total_urls?: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  risk_score?: number;
}

export interface ReportMeta {
  scanner: string;
  version: string;
  target: string;
  scan_date: string;
  duration_secs: number;
}

export interface Inventory {
  languages: string[];
  frameworks: string[];
  entrypoints: string[];
}

export interface RiskBreakdown {
  secrets: number;
  sinks: number;
  config: number;
  sca: number;
  iac: number;
}

export interface AttackPlanEntry {
  url: string;
  method: string;
  params: string[];
  reason: string;
}

export interface StaticAnalysis {
  inventory: Inventory;
  risk_score: number;
  risk_breakdown: RiskBreakdown;
  detection_checks?: Array<{
    id: string;
    triggered: boolean;
    severity: Severity;
    count: number;
  }>;
  attack_plan: AttackPlanEntry[];
}

export interface Correlation {
  id: string;
  finding_ids: string[];
  reason: string;
  elevated_severity?: Severity | null;
}

export interface Report {
  meta: ReportMeta;
  summary: ReportSummary;
  modules?: ModuleSummary[];
  correlations?: Correlation[];
  static?: StaticAnalysis;
  findings: Finding[];
}

export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export function parseReport(json: string): Report {
  const data = JSON.parse(json) as Report;
  if (!data || !Array.isArray(data.findings)) {
    throw new Error("Invalid RustZAP report: missing findings array");
  }
  return data;
}

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const sd = SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity];
    if (sd !== 0) {
      return sd;
    }
    const fileA = a.location?.file ?? "";
    const fileB = b.location?.file ?? "";
    if (fileA !== fileB) {
      return fileA.localeCompare(fileB);
    }
    return (a.location?.line_start ?? 0) - (b.location?.line_start ?? 0);
  });
}

export function formatSummaryLine(summary: ReportSummary, staticRisk?: number): string {
  const risk = staticRisk ?? summary.risk_score;
  const parts: string[] = [];
  if (risk !== undefined) {
    parts.push(`risk ${risk}`);
  }
  parts.push(`${summary.total_findings} finding(s)`);
  const sev: string[] = [];
  if (summary.critical) sev.push(`${summary.critical} critical`);
  if (summary.high) sev.push(`${summary.high} high`);
  if (summary.medium) sev.push(`${summary.medium} medium`);
  if (summary.low) sev.push(`${summary.low} low`);
  if (summary.info) sev.push(`${summary.info} info`);
  if (sev.length) {
    parts.push(sev.join(", "));
  }
  return parts.join(" · ");
}

export function findingLocationLabel(finding: Finding): string | undefined {
  const loc = finding.location;
  if (!loc?.file?.trim()) {
    if (/^https?:\/\//i.test(finding.url)) {
      return finding.url;
    }
    return undefined;
  }
  const line = loc.line_start > 0 ? `:${loc.line_start}` : "";
  return `${loc.file}${line}`;
}
