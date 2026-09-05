import * as vscode from "vscode";
import { Finding, formatSummaryLine, Report } from "./report";

export async function showFindingDetails(finding: Finding): Promise<void> {
  const md = buildFindingMarkdown(finding);
  const doc = await vscode.workspace.openTextDocument({
    language: "markdown",
    content: md,
  });
  await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
}

export async function showReportSummary(report: Report): Promise<void> {
  const md = buildReportMarkdown(report);
  const doc = await vscode.workspace.openTextDocument({
    language: "markdown",
    content: md,
  });
  await vscode.window.showTextDocument(doc, { preview: true, viewColumn: vscode.ViewColumn.Beside });
}

export async function openReportJson(reportPath: string): Promise<void> {
  const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(reportPath));
  await vscode.window.showTextDocument(doc, { preview: false });
}

function buildFindingMarkdown(finding: Finding): string {
  const lines: string[] = [
    `# ${finding.title}`,
    "",
    `| | |`,
    `|---|---|`,
    `| **Severity** | ${finding.severity.toUpperCase()} |`,
    `| **Plugin** | \`${finding.plugin}\` |`,
  ];
  if (finding.confidence) {
    lines.push(`| **Confidence** | ${finding.confidence} |`);
  }
  if (finding.cwe) {
    lines.push(`| **CWE** | ${finding.cwe} |`);
  }
  if (finding.owasp_category) {
    lines.push(`| **OWASP** | ${finding.owasp_category} |`);
  }
  if (finding.location?.file) {
    const line = finding.location.line_start > 0 ? `:${finding.location.line_start}` : "";
    lines.push(`| **Location** | \`${finding.location.file}${line}\` |`);
  }
  if (finding.url) {
    lines.push(`| **URL** | ${finding.url} |`);
  }
  lines.push("", "## Description", "", finding.description, "", "## Remediation", "", finding.solution);
  if (finding.evidence) {
    lines.push("", "## Evidence", "", "```", finding.evidence, "```");
  }
  if (finding.parameter) {
    lines.push("", `Parameter: \`${finding.parameter}\``);
  }
  return lines.join("\n");
}

function buildReportMarkdown(report: Report): string {
  const lines: string[] = [
    "# RustZAP report",
    "",
    `**Target:** ${report.meta.target}`,
    `**Scanner:** ${report.meta.scanner} ${report.meta.version}`,
    `**Date:** ${report.meta.scan_date}`,
    "",
    "## Summary",
    "",
    formatSummaryLine(report.summary, report.static?.risk_score),
    "",
  ];

  const st = report.static;
  if (st) {
    lines.push("## Static analysis", "");
    if (st.inventory.languages.length) {
      lines.push(`- **Languages:** ${st.inventory.languages.join(", ")}`);
    }
    if (st.inventory.frameworks.length) {
      lines.push(`- **Frameworks:** ${st.inventory.frameworks.join(", ")}`);
    }
    if (st.inventory.entrypoints.length) {
      lines.push(`- **Entrypoints:** ${st.inventory.entrypoints.join(", ")}`);
    }
    const rb = st.risk_breakdown;
    lines.push(
      "",
      "**Risk breakdown:**",
      `secrets ${rb.secrets}, sinks ${rb.sinks}, config ${rb.config}, sca ${rb.sca}, iac ${rb.iac}`,
      ""
    );
    if (st.attack_plan.length) {
      lines.push("## Attack plan", "");
      for (const e of st.attack_plan) {
        const params = e.params.length ? ` — params: ${e.params.join(", ")}` : "";
        lines.push(`- \`${e.method}\` ${e.url}${params} (${e.reason})`);
      }
      lines.push("");
    }
  }

  if (report.modules?.length) {
    lines.push("## Modules", "");
    for (const m of report.modules) {
      if (m.quiet && m.findings === 0) {
        continue;
      }
      const max = m.max_severity ? ` · max ${m.max_severity}` : "";
      lines.push(`- \`${m.name}\`: ${m.findings}${max}`);
    }
    lines.push("");
  }

  lines.push("## Findings", "");
  for (const f of report.findings) {
    const loc = f.location?.file
      ? ` (\`${f.location.file}:${f.location.line_start}\`)`
      : "";
    lines.push(`- **${f.severity}** — ${f.title}${loc}`);
  }
  return lines.join("\n");
}
