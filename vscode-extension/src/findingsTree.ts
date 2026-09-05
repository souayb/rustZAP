import * as vscode from "vscode";
import {
  AttackPlanEntry,
  Correlation,
  Finding,
  findingLocationLabel,
  formatSummaryLine,
  Report,
  sortFindings,
  SEVERITY_ORDER,
  Severity,
  StaticAnalysis,
} from "./report";
import { attackPlanTargetUrl } from "./session";
import { resolveFindingFileUri } from "./diagnostics";
import { showFindingDetails } from "./reportView";

export type RustZapTreeItem =
  | SummaryItem
  | SectionItem
  | DetailItem
  | AttackPlanItem
  | CorrelationItem
  | SeverityGroupItem
  | FindingItem;

export class SummaryItem extends vscode.TreeItem {
  constructor(report: Report) {
    const label = formatSummaryLine(report.summary, report.static?.risk_score);
    super(label, vscode.TreeItemCollapsibleState.None);
    this.contextValue = "summary";
    this.iconPath = new vscode.ThemeIcon("dashboard");
    this.description = report.meta.target.length > 48
      ? `…${report.meta.target.slice(-44)}`
      : report.meta.target;
    this.command = {
      command: "rustzap.showReportSummary",
      title: "Open Report Summary",
    };
    this.tooltip = buildReportTooltip(report);
  }
}

export class SectionItem extends vscode.TreeItem {
  constructor(
    label: string,
    public readonly sectionId: "inventory" | "attackPlan" | "attackPaths" | "findings",
    count: number,
    icon: string
  ) {
    super(`${label} (${count})`, vscode.TreeItemCollapsibleState.Expanded);
    this.contextValue = `section-${sectionId}`;
    this.iconPath = new vscode.ThemeIcon(icon);
  }
}

export class DetailItem extends vscode.TreeItem {
  constructor(label: string, detail: string, icon = "symbol-field") {
    super(label, vscode.TreeItemCollapsibleState.None);
    this.description = detail.length > 60 ? `${detail.slice(0, 57)}…` : detail;
    this.iconPath = new vscode.ThemeIcon(icon);
    this.tooltip = detail;
  }
}

export class AttackPlanItem extends vscode.TreeItem {
  constructor(
    public readonly entry: AttackPlanEntry,
    baseTarget: string | undefined
  ) {
    const params = entry.params.length ? ` [${entry.params.join(", ")}]` : "";
    super(`${entry.method} ${entry.url}${params}`, vscode.TreeItemCollapsibleState.None);
    this.description = entry.reason;
    this.contextValue = "attackPlan";
    this.iconPath = new vscode.ThemeIcon("target");
    this.tooltip = `${entry.reason}\n${entry.method} ${entry.url}`;

    const scanUrl = attackPlanTargetUrl(entry, baseTarget);
    if (scanUrl) {
      this.command = {
        command: "rustzap.scanAttackPlanEntry",
        title: "Scan suggested target",
        arguments: [scanUrl],
      };
    } else {
      this.command = {
        command: "rustzap.showReportSummary",
        title: "View attack plan context",
      };
    }
  }
}

export class CorrelationItem extends vscode.TreeItem {
  constructor(public readonly correlation: Correlation) {
    const sev = correlation.elevated_severity ? ` [${correlation.elevated_severity}]` : "";
    const label = correlation.reason.length > 72
      ? `${correlation.reason.slice(0, 69)}…`
      : correlation.reason;
    super(label, vscode.TreeItemCollapsibleState.None);
    this.description = `${correlation.finding_ids.length} finding(s)${sev}`;
    this.contextValue = "correlation";
    this.iconPath = new vscode.ThemeIcon("git-merge");
    const md = new vscode.MarkdownString();
    md.appendMarkdown(`${correlation.reason}\n\n`);
    if (correlation.elevated_severity) {
      md.appendMarkdown(`Elevated to: \`${correlation.elevated_severity}\`\n\n`);
    }
    md.appendMarkdown(`Correlated findings: ${correlation.finding_ids.length}`);
    this.tooltip = md;
  }
}

export class SeverityGroupItem extends vscode.TreeItem {
  constructor(
    public readonly severity: Severity,
    public readonly findings: Finding[]
  ) {
    super(
      severity.toUpperCase(),
      vscode.TreeItemCollapsibleState.Expanded
    );
    this.description = String(findings.length);
    this.contextValue = "severityGroup";
    this.iconPath = severityIcon(severity);
  }
}

export class FindingItem extends vscode.TreeItem {
  constructor(
    public readonly finding: Finding,
    workspaceRoot: string | undefined
  ) {
    super(finding.title, vscode.TreeItemCollapsibleState.None);
    this.description = findingLocationLabel(finding) ?? finding.plugin;
    this.tooltip = buildFindingTooltip(finding);
    this.contextValue = "finding";
    this.iconPath = severityIcon(finding.severity);

    const uri = resolveFindingFileUri(finding, workspaceRoot);
    if (uri && finding.location?.line_start) {
      this.command = {
        command: "rustzap.openFinding",
        title: "Open Finding",
        arguments: [finding, workspaceRoot],
      };
    } else if (/^https?:\/\//i.test(finding.url)) {
      this.command = {
        command: "vscode.open",
        title: "Open URL",
        arguments: [vscode.Uri.parse(finding.url)],
      };
    } else {
      this.command = {
        command: "rustzap.showFindingDetails",
        title: "Show Finding Details",
        arguments: [finding],
      };
    }
  }
}

function severityIcon(severity: Severity): vscode.ThemeIcon {
  switch (severity) {
    case "critical":
    case "high":
      return new vscode.ThemeIcon("error");
    case "medium":
      return new vscode.ThemeIcon("warning");
    case "low":
      return new vscode.ThemeIcon("info");
    default:
      return new vscode.ThemeIcon("circle-outline");
  }
}

function buildFindingTooltip(finding: Finding): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.appendMarkdown(`**${finding.title}** · \`${finding.severity}\`\n\n`);
  md.appendMarkdown(`${finding.description}\n\n`);
  if (finding.evidence) {
    md.appendMarkdown(`Evidence: \`${finding.evidence}\`\n\n`);
  }
  if (finding.confidence) {
    md.appendMarkdown(`Confidence: **${finding.confidence}**\n\n`);
  }
  if (finding.solution) {
    md.appendMarkdown(`*Fix:* ${finding.solution}\n\n`);
  }
  md.appendMarkdown(`Plugin: \`${finding.plugin}\``);
  return md;
}

function buildReportTooltip(report: Report): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.appendMarkdown(`**${report.meta.scanner}** ${report.meta.version}\n\n`);
  md.appendMarkdown(`Target: \`${report.meta.target}\`\n\n`);
  md.appendMarkdown(formatSummaryLine(report.summary, report.static?.risk_score));
  md.appendMarkdown("\n\n_Click to open full summary_");
  return md;
}

function inventoryChildren(staticBlock: StaticAnalysis): DetailItem[] {
  const items: DetailItem[] = [];
  if (staticBlock.inventory.languages.length) {
    items.push(new DetailItem("Languages", staticBlock.inventory.languages.join(", "), "symbol-string"));
  }
  if (staticBlock.inventory.frameworks.length) {
    items.push(new DetailItem("Frameworks", staticBlock.inventory.frameworks.join(", "), "package"));
  }
  if (staticBlock.inventory.entrypoints.length) {
    items.push(new DetailItem("Entrypoints", staticBlock.inventory.entrypoints.join(", "), "debug-start"));
  }
  const rb = staticBlock.risk_breakdown;
  items.push(
    new DetailItem(
      "Risk breakdown",
      `secrets ${rb.secrets}, sinks ${rb.sinks}, config ${rb.config}, sca ${rb.sca}, iac ${rb.iac}`,
      "graph"
    )
  );
  return items;
}

export class FindingsTreeProvider implements vscode.TreeDataProvider<RustZapTreeItem> {
  private _onDidChange = new vscode.EventEmitter<RustZapTreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChange.event;

  private report: Report | undefined;
  private workspaceRoot: string | undefined;

  refresh(report: Report, workspaceRoot: string | undefined): void {
    this.report = report;
    this.workspaceRoot = workspaceRoot;
    this._onDidChange.fire(undefined);
  }

  clear(): void {
    this.report = undefined;
    this._onDidChange.fire(undefined);
  }

  getTreeItem(element: RustZapTreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: RustZapTreeItem): RustZapTreeItem[] {
    if (!this.report) {
      return [new DetailItem("No results yet", "Run Analyze Workspace or Scan URL", "info")];
    }

    if (!element) {
      const roots: RustZapTreeItem[] = [new SummaryItem(this.report)];
      const st = this.report.static;
      if (st) {
        const inv = inventoryChildren(st);
        if (inv.length) {
          roots.push(new SectionItem("Inventory", "inventory", inv.length, "library"));
        }
        if (st.attack_plan.length) {
          roots.push(new SectionItem("Attack plan", "attackPlan", st.attack_plan.length, "target"));
        }
      }
      if (this.report.correlations?.length) {
        roots.push(
          new SectionItem("Attack paths", "attackPaths", this.report.correlations.length, "git-merge")
        );
      }
      const findings = sortFindings(this.report.findings);
      if (findings.length) {
        roots.push(new SectionItem("Findings", "findings", findings.length, "bug"));
      }
      return roots;
    }

    if (element instanceof SectionItem) {
      if (element.sectionId === "inventory" && this.report.static) {
        return inventoryChildren(this.report.static);
      }
      if (element.sectionId === "attackPlan" && this.report.static) {
        return this.report.static.attack_plan.map(
          (e) => new AttackPlanItem(e, this.report!.meta.target)
        );
      }
      if (element.sectionId === "attackPaths" && this.report.correlations) {
        return this.report.correlations.map((c) => new CorrelationItem(c));
      }
      if (element.sectionId === "findings") {
        return this.findingsBySeverity();
      }
    }

    if (element instanceof SeverityGroupItem) {
      return element.findings.map((f) => new FindingItem(f, this.workspaceRoot));
    }

    return [];
  }

  private findingsBySeverity(): SeverityGroupItem[] {
    const groups = new Map<Severity, Finding[]>();
    for (const f of sortFindings(this.report!.findings)) {
      const list = groups.get(f.severity) ?? [];
      list.push(f);
      groups.set(f.severity, list);
    }
    return (Object.keys(SEVERITY_ORDER) as Severity[])
      .filter((s) => (groups.get(s)?.length ?? 0) > 0)
      .map((s) => new SeverityGroupItem(s, groups.get(s)!));
  }
}

export async function openFinding(
  finding: Finding,
  workspaceRoot: string | undefined
) {
  const uri = resolveFindingFileUri(finding, workspaceRoot);
  if (!uri) {
    if (/^https?:\/\//i.test(finding.url)) {
      await vscode.env.openExternal(vscode.Uri.parse(finding.url));
      return;
    }
    await showFindingDetails(finding);
    return;
  }

  const doc = await vscode.workspace.openTextDocument(uri);
  const line = Math.max(0, (finding.location?.line_start ?? 1) - 1);
  const editor = await vscode.window.showTextDocument(doc);
  const pos = new vscode.Position(line, 0);
  editor.selection = new vscode.Selection(pos, pos);
  editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
}

export { showFindingDetails };
