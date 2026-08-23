import * as assert from "assert";
import * as path from "path";
import { parseReport } from "../report";
import {
  buildDiagnosticsDataMap,
  resolveFindingFilePath,
} from "../diagnosticsCore";

const FIXTURE = `{
  "meta": {
    "scanner": "RustZAP",
    "version": "0.1.0",
    "target": "/tmp/app",
    "scan_date": "2026-01-01T00:00:00Z",
    "duration_secs": 1
  },
  "summary": {
    "total_findings": 2,
    "critical": 0,
    "high": 1,
    "medium": 0,
    "low": 0,
    "info": 1
  },
  "findings": [
    {
      "id": "1",
      "title": "Possible secret",
      "severity": "high",
      "url": "file:///tmp/app/src/app.js#L10",
      "description": "Heuristic secret pattern",
      "solution": "Rotate credential",
      "plugin": "sast/secrets",
      "location": { "file": "src/app.js", "line_start": 10 }
    },
    {
      "id": "2",
      "title": "Missing HSTS",
      "severity": "medium",
      "url": "https://example.com",
      "description": "No Strict-Transport-Security header",
      "solution": "Add HSTS",
      "plugin": "passive/missing-headers"
    }
  ]
}`;

export function runDiagnosticsTests(): void {
  testParseReport();
  testStaticFindingDiagnostic();
  testDastFindingNoDiagnostic();
  testResolveRelativePath();
}

function testParseReport(): void {
  const report = parseReport(FIXTURE);
  assert.strictEqual(report.findings.length, 2);
  assert.strictEqual(report.findings[0].plugin, "sast/secrets");
}

function testStaticFindingDiagnostic(): void {
  const report = parseReport(FIXTURE);
  const finding = report.findings[0];
  const map = buildDiagnosticsDataMap([finding], "/tmp/app");
  assert.strictEqual(map.size, 1);
  const items = [...map.values()][0];
  assert.strictEqual(items[0].severity, "high");
  assert.ok(items[0].message.includes("Heuristic"));
}

function testDastFindingNoDiagnostic(): void {
  const report = parseReport(FIXTURE);
  const finding = report.findings[1];
  const map = buildDiagnosticsDataMap([finding], "/tmp/app");
  assert.strictEqual(map.size, 0);
  const all = buildDiagnosticsDataMap(report.findings, "/tmp/app");
  assert.strictEqual(all.size, 1);
}

function testResolveRelativePath(): void {
  const report = parseReport(FIXTURE);
  const finding = report.findings[0];
  const filePath = resolveFindingFilePath(finding, "/tmp/app");
  assert.ok(filePath);
  assert.ok(filePath!.endsWith(path.join("src", "app.js")));
}
