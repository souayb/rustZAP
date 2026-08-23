import * as vscode from "vscode";
import { ensureRustzapBinary, promptInstallRustzap } from "./binary";
import { ensureAnalyzeConsent, ensureScanLegalConsent, promptScanUrl } from "./consent";
import { applyDiagnostics, DIAGNOSTIC_SOURCE } from "./diagnostics";
import { FindingsTreeProvider, openFinding, showFindingDetails } from "./findingsTree";
import { log, logSection, showOutput } from "./output";
import { openReportJson, showReportSummary } from "./reportView";
import {
  createTempReportPaths,
  runAndLoadReport,
  workspaceRoot,
} from "./runner";
import {
  clearScanSession,
  getScanSession,
  ScanSession,
  setScanSession,
} from "./session";
import { focusFindingsView, hideStatusBar, refreshStatusBarFromSession } from "./statusBar";

let diagnostics: vscode.DiagnosticCollection;
let treeProvider: FindingsTreeProvider;
let saveListener: vscode.Disposable | undefined;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection(DIAGNOSTIC_SOURCE);
  context.subscriptions.push(diagnostics);

  treeProvider = new FindingsTreeProvider();
  context.subscriptions.push(
    vscode.window.registerTreeDataProvider("rustzap.findings", treeProvider)
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("rustzap.analyzeWorkspace", () =>
      analyzeWorkspace(context)
    ),
    vscode.commands.registerCommand("rustzap.scanUrl", () => scanUrl(context)),
    vscode.commands.registerCommand("rustzap.scanAttackPlanEntry", (url: string) =>
      scanUrl(context, url)
    ),
    vscode.commands.registerCommand("rustzap.clearFindings", () => clearFindings()),
    vscode.commands.registerCommand("rustzap.showOutput", () => showOutput()),
    vscode.commands.registerCommand("rustzap.openFinding", (finding, root?: string) =>
      openFinding(finding, root ?? workspaceRoot())
    ),
    vscode.commands.registerCommand("rustzap.showFindingDetails", (finding) =>
      showFindingDetails(finding)
    ),
    vscode.commands.registerCommand("rustzap.showReportSummary", async () => {
      const session = getScanSession();
      if (session) {
        await showReportSummary(session.report);
        return;
      }
      await vscode.window.showInformationMessage("No RustZAP report loaded yet.");
    }),
    vscode.commands.registerCommand("rustzap.openLastReport", async () => {
      const session = getScanSession();
      if (session) {
        await openReportJson(session.reportPath);
        return;
      }
      await vscode.window.showInformationMessage("No RustZAP report loaded yet.");
    }),
    vscode.commands.registerCommand("rustzap.focusFindings", () => focusFindingsView())
  );

  registerOnSave(context);
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration((e) => {
      if (e.affectsConfiguration("rustzap.analyze.onSave")) {
        registerOnSave(context);
      }
      if (e.affectsConfiguration("rustzap.problems.infoSeverity")) {
        const session = getScanSession();
        if (session) {
          presentResults(session, { quiet: true });
        }
      }
    })
  );

  log("RustZAP extension activated.");
}

export function deactivate(): void {
  saveListener?.dispose();
  diagnostics?.clear();
  hideStatusBar();
}

function registerOnSave(context: vscode.ExtensionContext): void {
  saveListener?.dispose();
  saveListener = undefined;

  const onSave = Boolean(
    vscode.workspace.getConfiguration("rustzap").get("analyze.onSave", false)
  );
  if (!onSave) {
    return;
  }

  saveListener = vscode.workspace.onDidSaveTextDocument(async () => {
    await analyzeWorkspace(context, { quiet: true });
  });
  context.subscriptions.push(saveListener);
}

function clearFindings(): void {
  diagnostics.clear();
  treeProvider.clear();
  clearScanSession();
  hideStatusBar();
  vscode.window.showInformationMessage("RustZAP findings cleared.");
}

async function analyzeWorkspace(
  context: vscode.ExtensionContext,
  opts?: { quiet?: boolean }
) {
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    vscode.window.showErrorMessage("Open a workspace folder to analyze.");
    return;
  }

  const root = folder.uri.fsPath;
  if (!(await ensureAnalyzeConsent(context, root))) {
    return;
  }

  const tools = String(vscode.workspace.getConfiguration("rustzap").get("analyze.tools", "native"));
  await runScan(context, {
    kind: "analyze",
    quiet: opts?.quiet,
    workspaceRoot: root,
    argsBuilder: (paths) => [
      "analyze",
      root,
      "--tools",
      tools,
      "--yes",
      "-o",
      paths.jsonPath,
      "--sarif-out",
      paths.sarifPath,
    ],
    progressTitle: "RustZAP: Analyzing workspace…",
    logTitle: "Analyze workspace",
  });
}

async function scanUrl(context: vscode.ExtensionContext, presetUrl?: string) {
  const target = presetUrl ?? (await promptScanUrl());
  if (!target) {
    return;
  }

  const config = vscode.workspace.getConfiguration("rustzap");
  const passiveOnly = Boolean(config.get("scan.passiveOnly", true));
  const depth = Number(config.get("scan.depth", 1));
  const plugins = String(config.get("scan.plugins", "")).trim();
  const insecure = Boolean(config.get("scan.insecure", false));

  if (!presetUrl && !passiveOnly && plugins) {
    const extra = await vscode.window.showWarningMessage(
      "Active scan plugins are enabled. Only proceed if you have authorization.",
      { modal: true },
      "Continue",
      "Cancel"
    );
    if (extra !== "Continue") {
      return;
    }
  }

  if (!(await ensureScanLegalConsent(target, passiveOnly))) {
    return;
  }

  const root = workspaceRoot();
  await runScan(context, {
    kind: "scan",
    workspaceRoot: root,
    argsBuilder: (paths) => {
      const args = [
        "scan",
        "--target",
        target,
        "--depth",
        String(depth),
        "-o",
        paths.jsonPath,
        "--sarif-out",
        paths.sarifPath,
      ];
      if (passiveOnly) {
        args.push("--passive-only");
      } else if (plugins) {
        args.push("--plugins", plugins);
      }
      if (insecure) {
        args.push("--insecure");
      }
      return args;
    },
    progressTitle: "RustZAP: Scanning URL…",
    logTitle: `Scan ${target}`,
  });
}

interface RunScanOptions {
  kind: "analyze" | "scan";
  workspaceRoot: string | undefined;
  argsBuilder: (paths: { jsonPath: string; sarifPath: string }) => string[];
  progressTitle: string;
  logTitle: string;
  quiet?: boolean;
}

async function runScan(context: vscode.ExtensionContext, opts: RunScanOptions) {
  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: opts.progressTitle,
      cancellable: true,
    },
    async (progress, token) => {
      try {
        showOutput();
        logSection(opts.logTitle);
        progress.report({ message: "Resolving rustzap binary…" });

        const binary = await ensureRustzapBinary(opts.workspaceRoot, context.extensionPath);
        log(`Using rustzap: ${binary}`);
        const paths = createTempReportPaths(context, opts.kind);

        progress.report({ message: `Running rustzap ${opts.kind}…` });
        const result = await runAndLoadReport(
          binary,
          opts.argsBuilder(paths),
          paths.jsonPath,
          paths.sarifPath,
          token
        );

        const session: ScanSession = {
          report: result.report,
          reportPath: paths.jsonPath,
          sarifPath: paths.sarifPath,
          workspaceRoot: opts.workspaceRoot,
          kind: opts.kind,
        };
        setScanSession(session);
        presentResults(session, { quiet: opts.quiet });

        log(`Report: ${paths.jsonPath}`);
        log(`SARIF: ${paths.sarifPath}`);
      } catch (err) {
        if (err instanceof vscode.CancellationError) {
          log(`${opts.kind} cancelled.`);
          return;
        }
        const msg = err instanceof Error ? err.message : String(err);
        log(`Error: ${msg}`);
        if (msg.includes("not found") || msg.includes("ENOENT")) {
          await promptInstallRustzap(opts.workspaceRoot, context.extensionPath);
        } else if (!opts.quiet) {
          vscode.window.showErrorMessage(`RustZAP ${opts.kind} failed: ${msg}`);
        }
      }
    }
  );
}

function presentResults(session: ScanSession, options?: { quiet?: boolean }): void {
  treeProvider.refresh(session.report, session.workspaceRoot);
  const diagCount = applyDiagnostics(
    diagnostics,
    session.report.findings,
    session.workspaceRoot
  );
  refreshStatusBarFromSession();

  const summary = session.report.summary;
  const risk = session.report.static?.risk_score ?? summary.risk_score;
  const riskPart = risk !== undefined ? ` · risk ${risk}` : "";
  const message = `${summary.total_findings} finding(s)${riskPart} · ${diagCount} in Problems`;

  log(`Target: ${session.report.meta.target}`);
  log(message);

  if (!options?.quiet) {
    const actions = ["Open summary", "Open JSON"];
    if (session.report.static?.attack_plan.length) {
      actions.splice(1, 0, "View attack plan");
    }

    vscode.window.showInformationMessage(`RustZAP: ${message}`, ...actions).then((choice) => {
      if (choice === "Open summary") {
        void showReportSummary(session.report);
      } else if (choice === "View attack plan") {
        void focusFindingsView();
      } else if (choice === "Open JSON") {
        void openReportJson(session.reportPath);
      }
    });
  }
}
