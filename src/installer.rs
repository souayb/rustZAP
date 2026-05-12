//! OS-aware companion tool installer for the unified DevSecOps console.
//!
//! Detects the host OS and either prints or executes the right package-manager
//! commands to install the SDD's companion tools (Semgrep, Trivy, Gitleaks,
//! Checkov, Nmap, Nikto, Wapiti, tshark, Hashcat, John, Hydra, Medusa,
//! Aircrack-ng).
//!
//! Same coverage as `scripts/install-tools.sh` — the script is the canonical
//! reference and is also what the Dockerfile invokes at build time.

use anyhow::{Context, Result};
use colored::*;
use std::io::{self, Write};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Macos,
    Debian,
    Fedora,
    Arch,
    Alpine,
    Unknown,
}

impl Os {
    pub fn detect() -> Os {
        if cfg!(target_os = "macos") {
            return Os::Macos;
        }
        if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
            let mut id = String::new();
            let mut id_like = String::new();
            for line in content.lines() {
                if let Some(v) = line.strip_prefix("ID=") {
                    id = v.trim_matches('"').to_lowercase();
                } else if let Some(v) = line.strip_prefix("ID_LIKE=") {
                    id_like = v.trim_matches('"').to_lowercase();
                }
            }
            if let Some(os) = match_id(&id) {
                return os;
            }
            for like in id_like.split_whitespace() {
                if let Some(os) = match_id(like) {
                    return os;
                }
            }
        }
        Os::Unknown
    }

    pub fn label(&self) -> &'static str {
        match self {
            Os::Macos => "macOS (Homebrew)",
            Os::Debian => "Debian/Ubuntu (apt)",
            Os::Fedora => "Fedora/RHEL (dnf)",
            Os::Arch => "Arch/Manjaro (pacman)",
            Os::Alpine => "Alpine (apk)",
            Os::Unknown => "unknown",
        }
    }
}

fn match_id(id: &str) -> Option<Os> {
    match id {
        "debian" | "ubuntu" | "kali" | "raspbian" | "linuxmint" => Some(Os::Debian),
        "fedora" | "rhel" | "centos" | "rocky" | "almalinux" => Some(Os::Fedora),
        "arch" | "manjaro" | "endeavouros" => Some(Os::Arch),
        "alpine" => Some(Os::Alpine),
        _ => None,
    }
}

struct Tool {
    name: &'static str,
    macos: Option<&'static str>,
    debian: Option<&'static str>,
    fedora: Option<&'static str>,
    arch: Option<&'static str>,
    alpine: Option<&'static str>,
}

impl Tool {
    fn cmd_for(&self, os: Os) -> Option<&'static str> {
        match os {
            Os::Macos => self.macos,
            Os::Debian => self.debian,
            Os::Fedora => self.fedora,
            Os::Arch => self.arch,
            Os::Alpine => self.alpine,
            Os::Unknown => None,
        }
    }
}

// Mirrors scripts/install-tools.sh. Keep them in sync.
const TOOLS: &[Tool] = &[
    Tool {
        name: "semgrep",
        macos: Some("brew install semgrep"),
        debian: Some("$SUDO apt-get install -y pipx && pipx install semgrep"),
        fedora: Some("$SUDO dnf install -y pipx && pipx install semgrep"),
        arch: Some("$SUDO pacman -S --noconfirm python-pipx && pipx install semgrep"),
        alpine: Some("$SUDO apk add --no-cache python3 py3-pip && pip3 install --break-system-packages semgrep"),
    },
    Tool {
        name: "trivy",
        macos: Some("brew install aquasecurity/trivy/trivy"),
        debian: Some("curl -sfL https://aquasecurity.github.io/trivy-repo/deb/public.key | $SUDO gpg --dearmor -o /usr/share/keyrings/trivy.gpg && echo \"deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main\" | $SUDO tee /etc/apt/sources.list.d/trivy.list >/dev/null && $SUDO apt-get update && $SUDO apt-get install -y trivy"),
        fedora: Some("$SUDO dnf install -y https://github.com/aquasecurity/trivy/releases/latest/download/trivy_Linux-64bit.rpm"),
        arch: Some("$SUDO pacman -S --noconfirm trivy"),
        alpine: Some("$SUDO apk add --no-cache trivy"),
    },
    Tool {
        name: "gitleaks",
        macos: Some("brew install gitleaks"),
        debian: Some("GLV=8.18.4 && curl -sSL https://github.com/gitleaks/gitleaks/releases/download/v${GLV}/gitleaks_${GLV}_linux_x64.tar.gz | $SUDO tar -xz -C /usr/local/bin gitleaks"),
        fedora: Some("$SUDO dnf install -y gitleaks"),
        arch: Some("$SUDO pacman -S --noconfirm gitleaks"),
        alpine: Some("$SUDO apk add --no-cache gitleaks"),
    },
    Tool {
        name: "checkov",
        macos: Some("brew install checkov"),
        debian: Some("$SUDO apt-get install -y pipx && pipx install checkov"),
        fedora: Some("$SUDO dnf install -y pipx && pipx install checkov"),
        arch: Some("$SUDO pacman -S --noconfirm python-pipx && pipx install checkov"),
        alpine: Some("$SUDO apk add --no-cache python3 py3-pip && pip3 install --break-system-packages checkov"),
    },
    Tool {
        name: "nmap",
        macos: Some("brew install nmap"),
        debian: Some("$SUDO apt-get install -y nmap"),
        fedora: Some("$SUDO dnf install -y nmap"),
        arch: Some("$SUDO pacman -S --noconfirm nmap"),
        alpine: Some("$SUDO apk add --no-cache nmap"),
    },
    Tool {
        name: "nikto",
        macos: Some("brew install nikto"),
        debian: Some("$SUDO apt-get install -y nikto"),
        fedora: Some("$SUDO dnf install -y nikto"),
        arch: Some("$SUDO pacman -S --noconfirm nikto"),
        alpine: None,
    },
    Tool {
        name: "wapiti",
        macos: Some("brew install wapiti"),
        debian: Some("$SUDO apt-get install -y pipx && pipx install wapiti3"),
        fedora: Some("$SUDO dnf install -y pipx && pipx install wapiti3"),
        arch: Some("$SUDO pacman -S --noconfirm python-pipx && pipx install wapiti3"),
        alpine: Some("$SUDO apk add --no-cache python3 py3-pip && pip3 install --break-system-packages wapiti3"),
    },
    Tool {
        name: "tshark",
        macos: Some("brew install --cask wireshark"),
        debian: Some("$SUDO apt-get install -y tshark"),
        fedora: Some("$SUDO dnf install -y wireshark-cli"),
        arch: Some("$SUDO pacman -S --noconfirm wireshark-cli"),
        alpine: Some("$SUDO apk add --no-cache tshark"),
    },
    Tool {
        name: "hashcat",
        macos: Some("brew install hashcat"),
        debian: Some("$SUDO apt-get install -y hashcat"),
        fedora: Some("$SUDO dnf install -y hashcat"),
        arch: Some("$SUDO pacman -S --noconfirm hashcat"),
        alpine: None,
    },
    Tool {
        name: "john",
        macos: Some("brew install john-jumbo"),
        debian: Some("$SUDO apt-get install -y john"),
        fedora: Some("$SUDO dnf install -y john"),
        arch: Some("$SUDO pacman -S --noconfirm john"),
        alpine: Some("$SUDO apk add --no-cache john"),
    },
    Tool {
        name: "hydra",
        macos: Some("brew install hydra"),
        debian: Some("$SUDO apt-get install -y hydra"),
        fedora: Some("$SUDO dnf install -y hydra"),
        arch: Some("$SUDO pacman -S --noconfirm hydra"),
        alpine: None,
    },
    Tool {
        name: "medusa",
        macos: Some("brew install medusa"),
        debian: Some("$SUDO apt-get install -y medusa"),
        fedora: Some("$SUDO dnf install -y medusa"),
        arch: Some("$SUDO pacman -S --noconfirm medusa"),
        alpine: None,
    },
    Tool {
        name: "aircrack-ng",
        macos: Some("brew install aircrack-ng"),
        debian: Some("$SUDO apt-get install -y aircrack-ng"),
        fedora: Some("$SUDO dnf install -y aircrack-ng"),
        arch: Some("$SUDO pacman -S --noconfirm aircrack-ng"),
        alpine: Some("$SUDO apk add --no-cache aircrack-ng"),
    },
];

fn is_installed(cmd: &str) -> bool {
    Command::new("/usr/bin/env")
        .args(["sh", "-c", &format!("command -v {} >/dev/null 2>&1", cmd)])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn sudo_prefix() -> &'static str {
    // Detect root once; cache through process.
    if is_root() {
        ""
    } else {
        "sudo"
    }
}

fn is_root() -> bool {
    Command::new("/usr/bin/env")
        .args(["sh", "-c", "[ \"$(id -u)\" = \"0\" ]"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn resolve(cmd: &str) -> String {
    cmd.replace("$SUDO", sudo_prefix())
}

/// Public entry point for the `install` subcommand.
pub async fn run(dry_run: bool, only: Option<String>, yes: bool, list: bool) -> Result<()> {
    let os = Os::detect();
    println!(
        "{} {}",
        "▶ Detected OS:".bright_white().bold(),
        os.label().bright_cyan()
    );

    if os == Os::Unknown {
        anyhow::bail!(
            "Unsupported OS — install companion tools manually (see SDD section 4)"
        );
    }

    if list {
        return list_tools(os);
    }

    if dry_run {
        println!("{}", "(dry run — no changes will be made)".dimmed());
    }

    let mut installed = 0u32;
    let mut skipped = 0u32;
    let mut failed = 0u32;

    for tool in TOOLS {
        if let Some(only) = &only {
            if tool.name != only.as_str() {
                continue;
            }
        }

        if is_installed(tool.name) {
            println!(
                "{} {} already installed",
                "✓".green(),
                tool.name.bright_white()
            );
            skipped += 1;
            continue;
        }

        let Some(raw) = tool.cmd_for(os) else {
            println!(
                "{} {} — not packaged on {}, skipping",
                "·".dimmed(),
                tool.name,
                os.label()
            );
            skipped += 1;
            continue;
        };

        let cmd = resolve(raw);
        println!(
            "{} {}",
            "▶".bright_yellow(),
            tool.name.bright_white().bold()
        );
        println!("  {} {}", "$".dimmed(), cmd.bright_blue());

        if dry_run {
            skipped += 1;
            continue;
        }

        if !yes && !confirm("  Install? [Y/n] ")? {
            println!("  skipped");
            skipped += 1;
            continue;
        }

        match run_shell(&cmd) {
            Ok(true) => {
                println!("  {} installed", "✓".green());
                installed += 1;
            }
            Ok(false) => {
                println!("  {} non-zero exit", "✗".red());
                failed += 1;
            }
            Err(e) => {
                println!("  {} {}", "✗".red(), e);
                failed += 1;
            }
        }
    }

    println!(
        "\n{} installed={} skipped={} failed={}",
        "Done —".bright_white().bold(),
        installed,
        skipped,
        failed
    );

    if failed > 0 {
        anyhow::bail!("{} tool(s) failed to install", failed);
    }
    Ok(())
}

fn list_tools(os: Os) -> Result<()> {
    println!("\n{:<14} INSTALL COMMAND ({})", "TOOL", os.label());
    println!("{}", "─".repeat(70));
    for tool in TOOLS {
        let cmd = tool
            .cmd_for(os)
            .map(resolve)
            .unwrap_or_else(|| "(not packaged)".to_string());
        let installed_badge = if is_installed(tool.name) {
            "✓".green().to_string()
        } else {
            "·".dimmed().to_string()
        };
        println!("{} {:<13} {}", installed_badge, tool.name, cmd);
    }
    println!();
    Ok(())
}

fn confirm(prompt: &str) -> Result<bool> {
    print!("{}", prompt);
    io::stdout().flush().ok();
    let mut buf = String::new();
    io::stdin()
        .read_line(&mut buf)
        .context("read confirmation")?;
    let ans = buf.trim().to_lowercase();
    Ok(ans.is_empty() || ans == "y" || ans == "yes")
}

fn run_shell(cmd: &str) -> Result<bool> {
    let status = Command::new("/usr/bin/env")
        .args(["bash", "-c", cmd])
        .status()
        .context("spawn bash")?;
    Ok(status.success())
}
