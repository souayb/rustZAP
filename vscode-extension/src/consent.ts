import * as vscode from "vscode";

const CONSENT_KEY = "analyzeConsentFolders";

/** One-time per-workspace-folder consent before --yes analyze. */
export async function ensureAnalyzeConsent(
  context: vscode.ExtensionContext,
  folderPath: string
): Promise<boolean> {
  const consented = context.globalState.get(CONSENT_KEY, []) as string[];
  const normalized = folderPath.replace(/\\/g, "/");
  if (consented.includes(normalized)) {
    return true;
  }

  const choice = await vscode.window.showWarningMessage(
    `RustZAP will read files in this folder for static analysis:\n${folderPath}`,
    { modal: true },
    "Allow analysis",
    "Cancel"
  );

  if (choice !== "Allow analysis") {
    return false;
  }

  await context.globalState.update(CONSENT_KEY, [...consented, normalized]);
  return true;
}

export async function ensureScanLegalConsent(
  targetUrl: string,
  passiveOnly: boolean
): Promise<boolean> {
  const mode = passiveOnly ? "passive-only" : "active (includes intrusive probes)";
  const choice = await vscode.window.showWarningMessage(
    `Only scan systems you own or have explicit written permission to test. Unauthorized scanning is illegal.\n\nTarget: ${targetUrl}\nMode: ${mode}`,
    { modal: true },
    "Run scan",
    "Cancel"
  );
  return choice === "Run scan";
}

export async function promptScanUrl(): Promise<string | undefined> {
  const url = await vscode.window.showInputBox({
    title: "RustZAP: Scan URL",
    prompt: "HTTPS target URL (must be authorized)",
    placeHolder: "https://example.com",
    validateInput: (value) => {
      const v = value.trim();
      if (!v) {
        return "URL is required";
      }
      if (!/^https?:\/\/.+/i.test(v)) {
        return "Enter a valid http(s) URL";
      }
      return undefined;
    },
  });
  return url?.trim();
}
