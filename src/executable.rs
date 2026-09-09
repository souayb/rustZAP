//! Shared executable discovery. Never invokes a Unix shell and never caches PATH.
use std::path::{Path, PathBuf};

/// One fresh discovery snapshot, shared across a tool-list refresh.
/// Individual launches always take a new snapshot.
pub struct Discovery {
    dirs: Vec<PathBuf>,
    extensions: Vec<String>,
}
impl Default for Discovery {
    fn default() -> Self {
        Self {
            dirs: search_dirs(),
            extensions: extensions(),
        }
    }
}
impl Discovery {
    pub fn find(&self, name: &str) -> Option<PathBuf> {
        let key = format!(
            "RUSTZAP_TOOL_{}",
            name.to_ascii_uppercase().replace('-', "_")
        );
        if let Some(path) = std::env::var_os(key) {
            return executable_path(Path::new(&path));
        }
        find_in(name, &self.dirs, cfg!(windows), &self.extensions)
    }
}
pub fn find(name: &str) -> Option<PathBuf> {
    Discovery::default().find(name)
}

pub fn require(name: &str) -> std::io::Result<PathBuf> {
    find(name).ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound,
        format!("{name} not found; run `rustzap install` for the full isolated environment, or set RUSTZAP_TOOL_{} to its executable path", name.to_ascii_uppercase().replace('-', "_"))))
}

fn executable_path(path: &Path) -> Option<PathBuf> {
    // A scanner changes its child working directory to the analyzed repository.
    // Resolve relative PATH entries/overrides before that change.
    std::path::absolute(path).ok().filter(|p| executable(p))
}

fn executable(path: &Path) -> bool {
    let Ok(meta) = path.metadata() else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
}

fn extensions() -> Vec<String> {
    std::env::var("PATHEXT")
        .unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".into())
        .split(';')
        .filter(|e| e.starts_with('.') && e.chars().skip(1).all(|c| c.is_ascii_alphanumeric()))
        .map(str::to_ascii_lowercase)
        .collect()
}

fn find_in(name: &str, dirs: &[PathBuf], windows: bool, exts: &[String]) -> Option<PathBuf> {
    if name.contains(['/', '\\']) {
        return executable_path(Path::new(name));
    }
    for dir in dirs {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let candidate = dir.join(name);
        if executable(&candidate) {
            return executable_path(&candidate);
        }
        if windows && Path::new(name).extension().is_none() {
            for ext in exts {
                let path = dir.join(format!("{name}{ext}"));
                if executable(&path) {
                    return executable_path(&path);
                }
            }
        }
    }
    None
}

fn search_dirs() -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    #[cfg(windows)]
    {
        // Installers update the registry, not the environment of already-running apps.
        // Read both scopes on each discovery/launch, without changing the parent process.
        let root = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
        let powershell = PathBuf::from(root).join("System32/WindowsPowerShell/v1.0/powershell.exe");
        if let Ok(output) = std::process::Command::new(powershell).args([
            "-NoProfile", "-NonInteractive", "-Command",
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; foreach ($scope in 'Machine','User') { [Environment]::ExpandEnvironmentVariables([Environment]::GetEnvironmentVariable('Path', $scope)) }"
        ]).output() {
            if output.status.success() {
                for line in String::from_utf8_lossy(&output.stdout).lines() {
                    dirs.extend(std::env::split_paths(line));
                }
            }
        }
        for (var, tails) in [
            (
                "USERPROFILE",
                vec![".local/bin", "scoop/shims", "go/bin", ".cargo/bin"],
            ),
            (
                "LOCALAPPDATA",
                vec![
                    "Microsoft/WinGet/Links",
                    "Programs/Python/Scripts",
                    "Python/bin",
                ],
            ),
            ("APPDATA", vec!["Python/Scripts", "npm"]),
            ("ProgramData", vec!["chocolatey/bin"]),
            (
                "ProgramFiles",
                vec!["Nmap", "Wireshark", "Docker/Docker/resources/bin"],
            ),
            ("ProgramFiles(x86)", vec!["Nmap", "Wireshark"]),
        ] {
            if let Some(base) = std::env::var_os(var) {
                dirs.extend(
                    tails
                        .into_iter()
                        .map(|tail| PathBuf::from(&base).join(tail)),
                );
            }
        }
        // pip --user and python.org installers use versioned Python directories.
        for (var, tail) in [("APPDATA", "Python"), ("LOCALAPPDATA", "Programs/Python")] {
            if let Some(base) = std::env::var_os(var) {
                if let Ok(entries) = std::fs::read_dir(PathBuf::from(base).join(tail)) {
                    for entry in entries.flatten() {
                        if entry.file_name().to_string_lossy().starts_with("Python") {
                            dirs.push(entry.path().join("Scripts"));
                        }
                    }
                }
            }
        }
    }
    #[cfg(not(windows))]
    {
        if let Some(home_dir) = std::env::var_os("HOME") {
            for tail in [".local/bin", "go/bin", ".cargo/bin"] {
                dirs.push(PathBuf::from(&home_dir).join(tail));
            }
        }
        dirs.extend(
            [
                "/opt/homebrew/bin",
                "/usr/local/bin",
                "/usr/local/sbin",
                "/usr/sbin",
            ]
            .map(PathBuf::from),
        );
    }
    dirs
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn finds_windows_extensions_in_paths_with_spaces_and_refreshes() {
        let dir = std::env::temp_dir().join(format!(
            "rustzap tool discovery {}",
            crate::types::uuid_v4()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let dirs = vec![dir.clone()];
        let exts = vec![".exe".into(), ".cmd".into()];
        assert!(find_in("semgrep", &dirs, true, &exts).is_none());
        let path = dir.join("semgrep.exe");
        std::fs::write(&path, "fixture").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        assert_eq!(find_in("semgrep", &dirs, true, &exts), Some(path));
        assert!(find_in("semgrep", &dirs, false, &exts).is_none());
        std::fs::remove_dir_all(dir).unwrap();
    }
    #[test]
    fn directories_are_not_tools() {
        assert!(!executable(&std::env::temp_dir()));
    }
}
