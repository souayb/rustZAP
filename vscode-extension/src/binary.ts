import * as path from "path";
import * as vscode from "vscode";
import {
  ensureRustzapPath,
  findBuiltBinaryFrom,
  resolveRustzapPath,
} from "./binaryCore";

const INSTALL_URL = "https://github.com/souayb/rustZAP#installation";

function searchRoots(
  workspaceRoot: string | undefined,
  extensionPath: string | undefined
): string[] {
  const roots: string[] = [];
  if (workspaceRoot) {
    roots.push(workspaceRoot);
  }
  if (extensionPath) {
    roots.push(extensionPath);
    roots.push(path.dirname(extensionPath));
  }
  return [...new Set(roots)];
}

export async function resolveRustzapBinary(
  workspaceRoot: string | undefined,
  extensionPath?: string
): Promise<string | undefined> {
  const configured = String(vscode.workspace.getConfiguration("rustzap").get("path", "")).trim();
  return resolveRustzapPath({
    configuredPath: configured,
    searchRoots: searchRoots(workspaceRoot, extensionPath),
  });
}

export async function ensureRustzapBinary(
  workspaceRoot: string | undefined,
  extensionPath?: string
): Promise<string> {
  const configured = String(vscode.workspace.getConfiguration("rustzap").get("path", "")).trim();
  return ensureRustzapPath({
    configuredPath: configured,
    searchRoots: searchRoots(workspaceRoot, extensionPath),
  });
}

export function suggestedRustzapPath(
  workspaceRoot: string | undefined,
  extensionPath?: string
): string | undefined {
  for (const root of searchRoots(workspaceRoot, extensionPath)) {
    const built = findBuiltBinaryFrom(root);
    if (built) {
      return built;
    }
  }
  return undefined;
}

export async function promptInstallRustzap(
  workspaceRoot?: string,
  extensionPath?: string
) {
  const suggested = suggestedRustzapPath(workspaceRoot, extensionPath);
  const actions = ["Open install docs"];
  if (suggested) {
    actions.push("Copy suggested path");
  }

  const choice = await vscode.window.showErrorMessage(
    suggested
      ? `RustZAP CLI not found. Build with cargo build --release or set rustzap.path to: ${suggested}`
      : "RustZAP CLI not found. Install it or set rustzap.path in settings.",
    ...actions
  );

  if (choice === "Open install docs") {
    await vscode.env.openExternal(vscode.Uri.parse(INSTALL_URL));
  } else if (choice === "Copy suggested path" && suggested) {
    await vscode.env.clipboard.writeText(suggested);
    vscode.window.showInformationMessage("Copied suggested rustzap.path to clipboard.");
  }
}
