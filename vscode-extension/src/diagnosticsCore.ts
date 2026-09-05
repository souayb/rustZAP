import * as path from "path";
import { Finding, Severity } from "./report";

export interface DiagnosticData {
  filePath: string;
  lineStart: number;
  lineEnd: number;
  severity: Severity;
  message: string;
  plugin: string;
}

export function isHttpUrl(value: string): boolean {
  return /^https?:\/\//i.test(value.trim());
}

export function isFileLike(value: string): boolean {
  const t = value.trim();
  if (!t || isHttpUrl(t)) {
    return false;
  }
  if (t.startsWith("file://")) {
    return true;
  }
  return /^([a-zA-Z]:[\\/]|\.{0,2}[\\/])/.test(t) || t.includes("/") || t.includes("\\");
}

export function filePathFromLocation(file: string): string {
  const trimmed = file.trim();
  if (trimmed.startsWith("file://")) {
    try {
      const url = new URL(trimmed);
      if (process.platform === "win32" && url.pathname.startsWith("/") && /^\/[a-zA-Z]:/.test(url.pathname)) {
        return url.pathname.slice(1).replace(/\//g, "\\");
      }
      return decodeURIComponent(url.pathname);
    } catch {
      return trimmed.replace(/^file:\/\//, "");
    }
  }
  return trimmed;
}

export function resolveFindingFilePath(
  finding: Finding,
  workspaceRoot: string | undefined
): string | undefined {
  const loc = finding.location;
  if (!loc?.file || !isFileLike(loc.file)) {
    return undefined;
  }

  const filePath = filePathFromLocation(loc.file);
  if (path.isAbsolute(filePath)) {
    return filePath;
  }

  if (!workspaceRoot) {
    return undefined;
  }

  return path.join(workspaceRoot, filePath);
}

export function buildDiagnosticsDataMap(
  findings: Finding[],
  workspaceRoot: string | undefined
): Map<string, DiagnosticData[]> {
  const byFile = new Map<string, DiagnosticData[]>();

  for (const finding of findings) {
    const loc = finding.location;
    if (!loc?.file || !isFileLike(loc.file)) {
      continue;
    }

    const filePath = resolveFindingFilePath(finding, workspaceRoot);
    if (!filePath) {
      continue;
    }

    const lineStart = Math.max(1, loc.line_start || 1);
    const lineEnd = loc.line_end && loc.line_end > 0 ? loc.line_end : lineStart;
    const parts = [finding.description];
    if (finding.solution) {
      parts.push(`Fix: ${finding.solution}`);
    }
    if (finding.plugin) {
      parts.push(`Plugin: ${finding.plugin}`);
    }

    const data: DiagnosticData = {
      filePath,
      lineStart,
      lineEnd,
      severity: finding.severity,
      message: parts.join("\n\n"),
      plugin: finding.plugin,
    };

    const list = byFile.get(filePath) ?? [];
    list.push(data);
    byFile.set(filePath, list);
  }

  return byFile;
}
