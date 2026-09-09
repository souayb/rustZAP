//! OS-aware companion tool installer for the unified DevSecOps console.
//!
//! Detects the host OS and either prints or executes the right package-manager
//! commands to install the SDD's companion tools (Semgrep, Trivy, Gitleaks,
//! Checkov, Nmap, Nikto, Wapiti, tshark, Hashcat, John, Hydra, Medusa,
//! Aircrack-ng).
//!
//! Full Kali Docker installation is the default. Native package-manager
//! installation is explicit; detection uses the same resolver as execution.

use anyhow::{Context, Result};
use colored::*;
use std::io::{self, Write};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Windows,
    Macos,
    Debian,
    Fedora,
    Arch,
    Alpine,
    Unknown,
}

impl Os {
    pub fn detect() -> Os {
        if cfg!(windows) {
            return Os::Windows;
        }
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
            Os::Windows => "Windows",
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
            Os::Unknown | Os::Windows => None,
        }
    }
}

// Mirrors scripts/install-tools.sh. Keep them in sync.
const TOOLS: &[Tool] = &[
    Tool {
        name: "nuclei",
        macos: Some("brew install nuclei"),
        debian: Some("$SUDO apt-get install -y nuclei"),
        fedora: None, arch: Some("$SUDO pacman -S --noconfirm nuclei"), alpine: None,
    },
    Tool {
        name: "wifite",
        macos: None, debian: Some("$SUDO apt-get install -y wifite"),
        fedora: None, arch: Some("$SUDO pacman -S --noconfirm wifite"), alpine: None,
    },
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
        debian: Some("$SUDO apt-get install -y gitleaks"),
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
    crate::executable::find(cmd).is_some()
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
pub async fn run(
    dry_run: bool,
    only: Option<String>,
    yes: bool,
    list: bool,
    native: bool,
) -> Result<()> {
    let os = Os::detect();
    println!(
        "{} {}",
        "▶ Detected OS:".bright_white().bold(),
        os.label().bright_cyan()
    );

    if let Some(name) = only.as_deref() {
        anyhow::ensure!(TOOLS.iter().any(|t| t.name == name), "Unknown tool: {name}");
    }
    if list {
        return list_tools(os);
    }
    if !native && std::env::var_os("RUSTZAP_IN_DOCKER").is_none() {
        anyhow::ensure!(
            only.is_none(),
            "--tool requires --native; the isolated installation includes the full tool set"
        );
        return install_isolated(dry_run, yes);
    }
    if os == Os::Windows {
        anyhow::bail!("Native installation is not supported on Windows. Use `rustzap install` for Kali Docker. Existing native tools are detected by `rustzap install --list`.");
    }
    if os == Os::Unknown {
        anyhow::bail!("Unsupported OS — install companion tools manually (see SDD section 4)");
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
            Ok(true) if is_installed(tool.name) => {
                println!("  {} installed", "✓".green());
                installed += 1;
            }
            Ok(_) => {
                println!(
                    "  {} install failed or executable was not detected",
                    "✗".red()
                );
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
    let discovery = crate::executable::Discovery::default();
    println!("\n{:<14} INSTALL COMMAND ({})", "TOOL", os.label());
    println!("{}", "─".repeat(70));
    for tool in TOOLS {
        let cmd = tool
            .cmd_for(os)
            .map(resolve)
            .unwrap_or_else(|| "(not packaged)".to_string());
        let found = discovery.find(tool.name);
        let installed_badge = if found.is_some() {
            "✓".green().to_string()
        } else {
            "·".dimmed().to_string()
        };
        println!(
            "{} {:<13} {}",
            installed_badge,
            tool.name,
            found.map(|p| p.display().to_string()).unwrap_or(cmd)
        );
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

include!(concat!(env!("OUT_DIR"), "/build_files.rs"));

pub fn image_name() -> String {
    format!("rustzap:{}-full", env!("CARGO_PKG_VERSION"))
}

fn install_isolated(dry_run: bool, yes: bool) -> Result<()> {
    println!("Full installation: Kali Linux container with RustZap and companion tools.");
    list_tools(Os::detect())?;
    println!(
        "Host tools above are detected; the container has its own independent tool installation."
    );
    println!(
        "Build image {} from the source bundled with this executable.",
        image_name()
    );
    if dry_run {
        return Ok(());
    }
    let docker = crate::executable::require("docker").context("Install and start Docker Desktop (Windows/macOS) or Docker Engine (Linux), then run rustzap install again")?;
    anyhow::ensure!(
        Command::new(&docker)
            .args(["info"])
            .output()?
            .status
            .success(),
        "Docker is not running or is inaccessible; start Docker and retry"
    );
    if !yes && !confirm("Download and build the full isolated environment? [Y/n] ")? {
        return Ok(());
    }
    let dir = std::env::temp_dir().join(format!("rustzap-build-{}", crate::types::uuid_v4()));
    std::fs::create_dir(&dir)?;
    let result = (|| -> Result<()> {
        for (name, content) in BUILD_FILES {
            let path = dir.join(name);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, content)?;
        }
        // The inner build does not need another embedded build context.
        std::fs::write(dir.join("build.rs"), include_str!("../build.rs"))?;
        anyhow::ensure!(
            Command::new(&docker)
                .args(["build", "--tag", &image_name()])
                .arg(&dir)
                .status()?
                .success(),
            "Full image build failed; no successful installation was recorded"
        );
        anyhow::ensure!(
            Command::new(&docker)
                .args([
                    "run",
                    "--rm",
                    "--network=none",
                    "--cap-drop=ALL",
                    &image_name(),
                    "install",
                    "--list"
                ])
                .status()?
                .success(),
            "Container tool verification failed"
        );
        Ok(())
    })();
    let _ = std::fs::remove_dir_all(&dir);
    result?;
    println!("Installed. Start with `rustzap isolated` or `rustzap isolated analyze . --yes`.");
    Ok(())
}

pub fn run_isolated(
    args: Vec<String>,
    workspace: Option<std::path::PathBuf>,
    env_vars: Vec<String>,
) -> Result<()> {
    use std::io::IsTerminal;
    let docker = crate::executable::require("docker")?;
    let mut command = Command::new(docker);
    command.args([
        "run",
        "--rm",
        "--init",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "-i",
    ]);
    if std::io::stdin().is_terminal() && std::io::stdout().is_terminal() {
        command.arg("-t");
    }
    let dir = workspace.unwrap_or(std::env::current_dir()?);
    std::fs::create_dir_all(&dir)?;
    let dir = dir.canonicalize()?;
    for name in env_vars {
        anyhow::ensure!(
            !name.is_empty() && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'),
            "--env accepts variable names only"
        );
        command.args(["--env", &name]);
    }
    command.arg("--add-host=host.docker.internal:host-gateway");
    #[cfg(unix)]
    {
        let uid = Command::new("id").arg("-u").output()?;
        let gid = Command::new("id").arg("-g").output()?;
        anyhow::ensure!(
            uid.status.success() && gid.status.success(),
            "Cannot determine container user"
        );
        if String::from_utf8_lossy(&uid.stdout).trim() != "0" {
            command.arg("--user").arg(format!(
                "{}:{}",
                String::from_utf8_lossy(&uid.stdout).trim(),
                String::from_utf8_lossy(&gid.stdout).trim()
            ));
        }
        command.args(["--env", "HOME=/tmp"]);
    }
    let mount_dir = dir.display().to_string();
    #[cfg(windows)]
    let mount_dir = mount_dir
        .strip_prefix(r"\\?\")
        .unwrap_or(&mount_dir)
        .to_string();
    // --volume is a separate argument; no shell interpolation of paths or user flags.
    command
        .arg("--volume")
        .arg(format!("{mount_dir}:/workspace"));
    command
        .args(["--workdir", "/workspace", &image_name()])
        .args(args);
    anyhow::ensure!(
        command
            .status()
            .context("launch isolated RustZap; run rustzap install first")?
            .success(),
        "Isolated RustZap failed; run rustzap install if the image is missing"
    );
    Ok(())
}
