//! External pentesting tool integration for the unified DevSecOps platform.
//!
//! Detects which SDD-listed tools (Semgrep, Trivy, Gitleaks, Checkov, Nmap,
//! Nikto, Wapiti, Hashcat, John, Hydra, Medusa, Aircrack-ng, Wifite, Falco,
//! tshark) are installed on PATH, then runs them as child processes with
//! streaming stdout/stderr forwarded to the TUI as `ToolEvent`s.

use anyhow::Result;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::Command;
use tokio::sync::mpsc::UnboundedSender;

#[derive(Debug, Clone)]
pub struct ExternalTool {
    pub name: String,
    pub command: String,
    pub category: &'static str,
    pub role: &'static str,
    pub default_args: Vec<String>,
    pub needs_target: bool,
    pub installed: bool,
}

#[derive(Debug, Clone)]
pub enum ToolEvent {
    Started { tool: String, cmdline: String },
    Output { tool: String, line: String },
    Completed { tool: String, exit_code: i32 },
    Error { tool: String, error: String },
}

type ToolDef = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    Vec<&'static str>,
    bool,
);

fn definitions() -> Vec<ToolDef> {
    vec![
        // (name, cmd, category, role, default_args, needs_target)
        (
            "Semgrep",
            "semgrep",
            "SAST",
            "Static code analysis",
            vec!["scan", "--quiet", "--json", "."],
            false,
        ),
        (
            "Trivy",
            "trivy",
            "SCA",
            "Container/dep scanning",
            vec!["fs", "--quiet", "--format", "json", "."],
            false,
        ),
        (
            "Gitleaks",
            "gitleaks",
            "Secrets",
            "Secret detection",
            vec!["detect", "--no-banner"],
            false,
        ),
        (
            "Checkov",
            "checkov",
            "IaC",
            "Infra-as-code scanning",
            vec!["-d", ".", "--quiet", "--compact"],
            false,
        ),
        (
            "Nmap",
            "nmap",
            "Recon",
            "Network port/service map",
            vec!["-sV", "-T4"],
            true,
        ),
        (
            "Nikto",
            "nikto",
            "DAST",
            "Web vuln scanner",
            vec!["-h"],
            true,
        ),
        (
            "Wapiti",
            "wapiti",
            "DAST",
            "Web vuln scanner",
            vec!["-u"],
            true,
        ),
        (
            "tshark",
            "tshark",
            "Packet",
            "Packet capture",
            vec!["-c", "20"],
            false,
        ),
        (
            "Hashcat",
            "hashcat",
            "Cracking",
            "GPU hash cracking",
            vec!["--version"],
            false,
        ),
        (
            "John",
            "john",
            "Cracking",
            "Password cracker",
            vec!["--list=help"],
            false,
        ),
        (
            "Hydra",
            "hydra",
            "Auth",
            "Brute-force tool",
            vec!["-h"],
            false,
        ),
        (
            "Medusa",
            "medusa",
            "Auth",
            "Brute-force tool",
            vec!["-h"],
            false,
        ),
        (
            "Aircrack-ng",
            "aircrack-ng",
            "Wireless",
            "WiFi auditing",
            vec!["--help"],
            false,
        ),
        (
            "Wifite",
            "wifite",
            "Wireless",
            "WiFi auditing",
            vec!["--help"],
            false,
        ),
        (
            "Falco",
            "falco",
            "Runtime",
            "Runtime threat detection",
            vec!["--version"],
            false,
        ),
    ]
}

fn is_installed(cmd: &str) -> bool {
    std::process::Command::new("/usr/bin/env")
        .args([
            "sh",
            "-c",
            &format!("command -v {} >/dev/null 2>&1", shell_escape(cmd)),
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn shell_escape(s: &str) -> String {
    // Only allow simple command names; reject anything funky.
    if s.chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        s.to_string()
    } else {
        String::new()
    }
}

pub fn detect_tools() -> Vec<ExternalTool> {
    definitions()
        .into_iter()
        .map(|(name, cmd, category, role, args, needs_target)| {
            let installed = is_installed(cmd);
            ExternalTool {
                name: name.to_string(),
                command: cmd.to_string(),
                category,
                role,
                default_args: args.into_iter().map(String::from).collect(),
                needs_target,
                installed,
            }
        })
        .collect()
}

pub async fn run_tool(
    tool: ExternalTool,
    target: Option<String>,
    tx: UnboundedSender<ToolEvent>,
) -> Result<()> {
    if !tool.installed {
        let _ = tx.send(ToolEvent::Error {
            tool: tool.name.clone(),
            error: format!("{} is not installed on this system", tool.command),
        });
        return Ok(());
    }

    let mut cmd = Command::new(&tool.command);
    cmd.args(&tool.default_args);

    let mut cmdline = format!("{} {}", tool.command, tool.default_args.join(" "));
    if tool.needs_target {
        if let Some(t) = target.as_ref() {
            cmd.arg(t);
            cmdline.push(' ');
            cmdline.push_str(t);
        } else {
            let _ = tx.send(ToolEvent::Error {
                tool: tool.name.clone(),
                error: "Tool requires a target URL/host (set on Scan tab)".to_string(),
            });
            return Ok(());
        }
    }

    cmd.stdout(std::process::Stdio::piped());
    cmd.stderr(std::process::Stdio::piped());
    cmd.kill_on_drop(true);

    let _ = tx.send(ToolEvent::Started {
        tool: tool.name.clone(),
        cmdline,
    });

    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            let _ = tx.send(ToolEvent::Error {
                tool: tool.name.clone(),
                error: format!("spawn failed: {}", e),
            });
            return Ok(());
        }
    };

    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let tool_name = tool.name.clone();

    if let Some(stdout) = stdout {
        let tx = tx.clone();
        let name = tool_name.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send(ToolEvent::Output {
                    tool: name.clone(),
                    line,
                });
            }
        });
    }
    if let Some(stderr) = stderr {
        let tx = tx.clone();
        let name = tool_name.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stderr).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let _ = tx.send(ToolEvent::Output {
                    tool: name.clone(),
                    line: format!("[err] {}", line),
                });
            }
        });
    }

    let status = match child.wait().await {
        Ok(s) => s,
        Err(e) => {
            let _ = tx.send(ToolEvent::Error {
                tool: tool_name.clone(),
                error: format!("wait failed: {}", e),
            });
            return Ok(());
        }
    };

    let _ = tx.send(ToolEvent::Completed {
        tool: tool_name,
        exit_code: status.code().unwrap_or(-1),
    });

    Ok(())
}
