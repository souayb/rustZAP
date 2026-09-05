import * as vscode from "vscode";

const CHANNEL_NAME = "RustZAP";

let channel: vscode.OutputChannel | undefined;

export function getOutputChannel(): vscode.OutputChannel {
  if (!channel) {
    channel = vscode.window.createOutputChannel(CHANNEL_NAME);
  }
  return channel;
}

export function showOutput(): void {
  getOutputChannel().show(true);
}

export function log(line: string): void {
  getOutputChannel().appendLine(line);
}

export function logSection(title: string): void {
  const ch = getOutputChannel();
  ch.appendLine("");
  ch.appendLine(`=== ${title} ===`);
}
