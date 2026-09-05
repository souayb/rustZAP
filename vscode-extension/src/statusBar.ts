import * as vscode from "vscode";
import { getScanSession, sessionSummary } from "./session";

let item: vscode.StatusBarItem | undefined;

export function initStatusBar(): vscode.StatusBarItem {
  if (!item) {
    item = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 50);
    item.command = "rustzap.focusFindings";
    item.tooltip = "RustZAP findings — click to focus sidebar";
  }
  return item;
}

export function updateStatusBar(text: string, tooltip?: string): void {
  const bar = initStatusBar();
  bar.text = text;
  if (tooltip) {
    bar.tooltip = tooltip;
  }
  bar.show();
}

export function refreshStatusBarFromSession(): void {
  const session = getScanSession();
  if (!session) {
    item?.hide();
    return;
  }
  const target = session.report.meta.target;
  updateStatusBar(
    `$(shield) RustZAP: ${sessionSummary(session)}`,
    `Target: ${target}\nClick to focus findings`
  );
}

export function hideStatusBar(): void {
  item?.hide();
}

export async function focusFindingsView(): Promise<void> {
  await vscode.commands.executeCommand("rustzap.findings.focus");
}
