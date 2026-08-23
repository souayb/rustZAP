import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { spawn } from "child_process";
import * as vscode from "vscode";
import { log } from "./output";
import { parseReport, Report } from "./report";

export interface RunResult {
  report: Report;
  reportPath: string;
  sarifPath: string;
  stdout: string;
  stderr: string;
}

export interface TempReportPaths {
  jsonPath: string;
  sarifPath: string;
}

/** Create report files under extension global storage (never repo root). */
export function createTempReportPaths(context: vscode.ExtensionContext, prefix: string): TempReportPaths {
  const dir = path.join(context.globalStorageUri.fsPath, "reports");
  fs.mkdirSync(dir, { recursive: true });
  const stamp = Date.now();
  const base = path.join(dir, `${prefix}-${stamp}`);
  return {
    jsonPath: `${base}.json`,
    sarifPath: `${base}.sarif`,
  };
}

function readFileUtf8(filePath: string): string {
  return fs.readFileSync(filePath, "utf8");
}

export async function runRustzap(
  binary: string,
  args: string[],
  token: vscode.CancellationToken
): Promise<{ stdout: string; stderr: string; code: number | null }> {
  return new Promise((resolve, reject) => {
    log(`$ ${binary} ${args.join(" ")}`);

    const child = spawn(binary, args, {
      cwd: vscode.workspace.workspaceFolders?.[0]?.uri.fsPath ?? process.cwd(),
      env: { ...process.env },
      shell: process.platform === "win32",
    });

    let stdout = "";
    let stderr = "";

    child.stdout.on("data", (chunk: Buffer) => {
      const text = chunk.toString();
      stdout += text;
      for (const line of text.split(/\r?\n/)) {
        if (line.trim()) {
          log(line);
        }
      }
    });

    child.stderr.on("data", (chunk: Buffer) => {
      const text = chunk.toString();
      stderr += text;
      for (const line of text.split(/\r?\n/)) {
        if (line.trim()) {
          log(`[stderr] ${line}`);
        }
      }
    });

    const onCancel = token.onCancellationRequested(() => {
      log("Cancellation requested — terminating rustzap…");
      child.kill("SIGTERM");
      setTimeout(() => {
        if (!child.killed) {
          child.kill("SIGKILL");
        }
      }, 3000);
    });

    child.on("error", (err) => {
      onCancel.dispose();
      reject(err);
    });

    child.on("close", (code) => {
      onCancel.dispose();
      if (token.isCancellationRequested) {
        reject(new vscode.CancellationError());
        return;
      }
      resolve({ stdout, stderr, code });
    });
  });
}

export async function runAndLoadReport(
  binary: string,
  args: string[],
  jsonPath: string,
  sarifPath: string,
  token: vscode.CancellationToken
): Promise<RunResult> {
  const { stdout, stderr, code } = await runRustzap(binary, args, token);

  if (code !== 0 && !fs.existsSync(jsonPath)) {
    throw new Error(
      `rustzap exited with code ${code ?? "unknown"}${stderr ? `: ${stderr.trim()}` : ""}`
    );
  }

  if (!fs.existsSync(jsonPath)) {
    throw new Error("RustZAP did not write a JSON report.");
  }

  const report = parseReport(readFileUtf8(jsonPath));
  return { report, reportPath: jsonPath, sarifPath, stdout, stderr };
}

export function workspaceRoot(): string | undefined {
  return vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
}

export function tempDirHint(): string {
  return path.join(os.tmpdir(), "rustzap-vscode");
}
