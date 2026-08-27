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

export interface AdScanInputs {
  domain: string;
  dcIp: string;
  targets: string[];
  username?: string;
  password?: string;
  nullAuth: boolean;
}

/** Authorization gate for an AD scan (modal, every run — not persisted). */
export async function ensureAdAuthConsent(domain: string, dcIp: string): Promise<boolean> {
  const choice = await vscode.window.showWarningMessage(
    `RustZAP will send LDAP and NTLM authentication traffic to Active Directory hosts.\n\n` +
      `Domain: ${domain}\nDC: ${dcIp}\n\n` +
      `This is intrusive network probing. Only scan AD you own or are explicitly authorized to test.`,
    { modal: true },
    "Run AD scan",
    "Cancel"
  );
  return choice === "Run AD scan";
}

/** Collect AD scan inputs. Credentials are prompted, never stored in settings. */
export async function promptAdInputs(defaultDomain: string, defaultDcIp: string): Promise<AdScanInputs | undefined> {
  const domain = (
    await vscode.window.showInputBox({
      title: "RustZAP: Active Directory — Domain",
      prompt: "AD domain FQDN",
      value: defaultDomain,
      placeHolder: "corp.local",
      validateInput: (v) => (v.trim() ? undefined : "Domain is required"),
    })
  )?.trim();
  if (!domain) {
    return undefined;
  }

  const dcIp = (
    await vscode.window.showInputBox({
      title: "RustZAP: Active Directory — Domain Controller IP",
      prompt: "Domain controller IP (LDAP bind + domain DNS)",
      value: defaultDcIp,
      placeHolder: "10.0.0.1",
      validateInput: (v) => (v.trim() ? undefined : "DC IP is required"),
    })
  )?.trim();
  if (!dcIp) {
    return undefined;
  }

  const targetsRaw = await vscode.window.showInputBox({
    title: "RustZAP: Active Directory — Targets (optional)",
    prompt: "Comma-separated hosts to probe; leave blank to use the DC",
    placeHolder: "dc01.corp.local, srv02.corp.local",
  });
  if (targetsRaw === undefined) {
    return undefined; // escaped
  }
  const targets = targetsRaw
    .split(",")
    .map((t) => t.trim())
    .filter(Boolean);

  const auth = await vscode.window.showQuickPick(
    [
      { label: "Authenticated bind", detail: "Provide username + password", value: "auth" },
      { label: "Anonymous (null auth)", detail: "Unauthenticated bind", value: "null" },
    ],
    { title: "RustZAP: Active Directory — Authentication", placeHolder: "Choose bind mode" }
  );
  if (!auth) {
    return undefined;
  }
  if (auth.value === "null") {
    return { domain, dcIp, targets, nullAuth: true };
  }

  const username = (
    await vscode.window.showInputBox({
      title: "RustZAP: Active Directory — Username",
      prompt: "Bind username (UPN built as user@domain)",
      placeHolder: "svc-account",
      validateInput: (v) => (v.trim() ? undefined : "Username is required"),
    })
  )?.trim();
  if (!username) {
    return undefined;
  }

  const password = await vscode.window.showInputBox({
    title: "RustZAP: Active Directory — Password",
    prompt: "Bind password (kept in memory only; passed to the CLI via an env var)",
    password: true,
    validateInput: (v) => (v ? undefined : "Password is required"),
  });
  if (password === undefined) {
    return undefined;
  }

  return { domain, dcIp, targets, username, password, nullAuth: false };
}
