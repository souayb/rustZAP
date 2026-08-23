import { AttackPlanEntry, Finding, Report } from "./report";

export interface ScanSession {
  report: Report;
  reportPath: string;
  sarifPath: string;
  workspaceRoot: string | undefined;
  kind: "analyze" | "scan";
}

let session: ScanSession | undefined;

export function setScanSession(next: ScanSession): void {
  session = next;
}

export function getScanSession(): ScanSession | undefined {
  return session;
}

export function clearScanSession(): void {
  session = undefined;
}

export function sessionSummary(session: ScanSession): string {
  const s = session.report.summary;
  const risk = session.report.static?.risk_score ?? s.risk_score;
  const bits = [`${s.total_findings} finding(s)`];
  if (risk !== undefined) {
    bits.unshift(`risk ${risk}`);
  }
  return bits.join(" · ");
}

export function attackPlanTargetUrl(entry: AttackPlanEntry, baseTarget?: string): string | undefined {
  const raw = entry.url.trim();
  if (/^https?:\/\//i.test(raw)) {
    return raw;
  }
  if (!baseTarget) {
    return undefined;
  }
  try {
    return new URL(raw, baseTarget.endsWith("/") ? baseTarget : `${baseTarget}/`).href;
  } catch {
    return undefined;
  }
}

export function isActionableFinding(finding: Finding): boolean {
  return Boolean(finding.location?.file?.trim()) || /^https?:\/\//i.test(finding.url);
}
