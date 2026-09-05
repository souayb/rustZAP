import * as vscode from "vscode";
import { Finding } from "./report";
import {
  buildDiagnosticsDataMap,
  DiagnosticData,
  isFileLike,
  resolveFindingFilePath,
} from "./diagnosticsCore";

export const DIAGNOSTIC_SOURCE = "RustZAP";

function infoSeverity(): vscode.DiagnosticSeverity {
  const mode = String(
    vscode.workspace.getConfiguration("rustzap").get("problems.infoSeverity", "information")
  );
  return mode === "hint"
    ? vscode.DiagnosticSeverity.Hint
    : vscode.DiagnosticSeverity.Information;
}

function severityToDiagnostic(severity: DiagnosticData["severity"]): vscode.DiagnosticSeverity {
  switch (severity) {
    case "critical":
    case "high":
      return vscode.DiagnosticSeverity.Error;
    case "medium":
      return vscode.DiagnosticSeverity.Warning;
    case "low":
      return vscode.DiagnosticSeverity.Information;
    case "info":
      return infoSeverity();
    default:
      return vscode.DiagnosticSeverity.Information;
  }
}

export function resolveFindingFileUri(
  finding: Finding,
  workspaceRoot: string | undefined
): vscode.Uri | undefined {
  const filePath = resolveFindingFilePath(finding, workspaceRoot);
  if (!filePath) {
    return undefined;
  }
  return vscode.Uri.file(filePath);
}

export function findingToDiagnostic(finding: Finding): vscode.Diagnostic | undefined {
  const loc = finding.location;
  if (!loc?.file || !isFileLike(loc.file)) {
    return undefined;
  }

  const line = Math.max(0, (loc.line_start || 1) - 1);
  const endLine = loc.line_end && loc.line_end > 0 ? loc.line_end - 1 : line;

  const range = new vscode.Range(
    new vscode.Position(line, 0),
    new vscode.Position(endLine, Number.MAX_SAFE_INTEGER)
  );

  const parts = [`**${finding.title}**`, finding.description];
  if (finding.evidence) {
    parts.push(`Evidence: ${finding.evidence}`);
  }
  if (finding.solution) {
    parts.push(`Fix: ${finding.solution}`);
  }

  const diag = new vscode.Diagnostic(
    range,
    parts.join("\n\n"),
    severityToDiagnostic(finding.severity)
  );
  diag.source = DIAGNOSTIC_SOURCE;
  diag.code = finding.plugin;
  return diag;
}

export function applyDiagnostics(
  collection: vscode.DiagnosticCollection,
  findings: Finding[],
  workspaceRoot: string | undefined
): number {
  collection.clear();
  const map = buildDiagnosticsDataMap(findings, workspaceRoot);
  let count = 0;

  for (const [filePath, items] of map) {
    const uri = vscode.Uri.file(filePath);
    const diags = items.map((item) => {
      const line = Math.max(0, item.lineStart - 1);
      const endLine = Math.max(line, item.lineEnd - 1);
      const range = new vscode.Range(
        new vscode.Position(line, 0),
        new vscode.Position(endLine, Number.MAX_SAFE_INTEGER)
      );
      const diag = new vscode.Diagnostic(range, item.message, severityToDiagnostic(item.severity));
      diag.source = DIAGNOSTIC_SOURCE;
      diag.code = item.plugin;
      return diag;
    });
    collection.set(uri, diags);
    count += diags.length;
  }

  return count;
}
