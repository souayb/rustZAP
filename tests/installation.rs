//! Installation preflight never needs elevated privileges or a Docker daemon.
use std::process::Command;

#[test]
fn full_setup_is_default_and_unknown_tools_fail() {
    let output = Command::new(env!("CARGO_BIN_EXE_rustzap"))
        .args(["install", "--dry-run"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Full installation: Kali Linux"));
    let output = Command::new(env!("CARGO_BIN_EXE_rustzap"))
        .args(["install", "--tool", "typo", "--dry-run"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("Unknown tool"));
}

#[cfg(unix)]
#[test]
fn installed_binary_build_context_is_complete_without_checkout() {
    use std::os::unix::fs::PermissionsExt;
    let root = std::env::temp_dir().join(format!(
        "rustzap install fixture {}",
        rustzap::types::uuid_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let docker = root.join("docker-fixture");
    std::fs::write(&docker, r#"#!/bin/sh
set -eu
case "$1" in
 info) exit 0 ;;
 build)
   for arg do context="$arg"; done
   for file in Cargo.toml Cargo.lock Dockerfile build.rs scope.example.yaml src/lib.rs src/installer.rs scripts/install-tools.sh; do
     test -s "$context/$file" || exit 21
   done
   exit 0 ;;
 run) exit 0 ;;
 *) exit 22 ;;
esac
"#).unwrap();
    std::fs::set_permissions(&docker, std::fs::Permissions::from_mode(0o700)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_rustzap"))
        .current_dir(&root)
        .env("RUSTZAP_TOOL_DOCKER", &docker)
        .args(["install", "--yes"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("Installed. Start"));
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn analyzer_executes_discovered_override_in_path_with_spaces() {
    let root = std::env::temp_dir().join(format!(
        "rustzap tool execution {}",
        rustzap::types::uuid_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let tool = root.join(if cfg!(windows) { "trivy.cmd" } else { "trivy" });
    #[cfg(windows)]
    std::fs::write(&tool, "@echo off\r\necho {\"Results\":[]}\r\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::write(&tool, "#!/bin/sh\nprintf '%s\\n' '{\"Results\":[]}'\n").unwrap();
        std::fs::set_permissions(&tool, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let report = root.join("report.json");
    let output = Command::new(env!("CARGO_BIN_EXE_rustzap"))
        .env("RUSTZAP_TOOL_TRIVY", &tool)
        .arg("analyze")
        .arg(&root)
        .args(["--tools", "trivy", "--yes", "--output"])
        .arg(&report)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(report.exists());
    std::fs::remove_dir_all(root).unwrap();
}
