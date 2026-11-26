//! Label secret findings `committed` vs `working-tree-only`.
//!
//! A secret that lives in git history is far more dangerous than one that only
//! exists in an untracked working-tree file (e.g. a local `.env`): the committed
//! one has likely been pushed and must be rotated *and* purged from history.
//!
//! We shell out to `git` in the analyzed repo (`ls-files` for tracked paths,
//! `log` for files ever committed). When the path is not a git repo or `git` is
//! missing, findings are returned unchanged.

use std::collections::HashSet;
use std::path::Path;
use std::process::Command;

use crate::types::{Finding, Severity};

/// True when the finding is a secret-class finding worth labeling.
fn is_secret(f: &Finding) -> bool {
    f.plugin == "sast/secrets" || f.plugin == "sast/js-secrets" || f.plugin.starts_with("secrets/")
}

fn run_git(repo: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Files ever recorded in git history (committed). `None` ⇒ not a git repo / no git.
fn committed_files(repo: &Path) -> Option<HashSet<String>> {
    // Confirm this is a work tree before trusting later calls.
    run_git(repo, &["rev-parse", "--is-inside-work-tree"])?;
    let log = run_git(
        repo,
        &[
            "log",
            "--all",
            "--pretty=format:",
            "--name-only",
            "--diff-filter=d",
        ],
    )?;
    Some(
        log.lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .map(|l| l.to_string())
            .collect(),
    )
}

/// Normalize a finding's file path to a repo-relative, forward-slash path so it
/// can be compared against `git` output.
fn repo_relative(repo: &Path, file: &str) -> String {
    let cleaned = file.strip_prefix("file://").unwrap_or(file);
    let cleaned = cleaned.split('#').next().unwrap_or(cleaned);
    let p = Path::new(cleaned);
    let rel = p.strip_prefix(repo).map(|r| r.to_path_buf());
    let s = match rel {
        Ok(r) => r.to_string_lossy().into_owned(),
        Err(_) => cleaned.to_string(),
    };
    s.replace('\\', "/")
}

fn bump(sev: Severity) -> Severity {
    match sev {
        Severity::Info => Severity::Low,
        Severity::Low => Severity::Medium,
        Severity::Medium => Severity::High,
        Severity::High | Severity::Critical => Severity::Critical,
    }
}

/// Annotate secret findings in-place with a committed/working-tree label and
/// raise committed secrets one severity step.
pub fn label_secrets(repo: &Path, findings: &mut [Finding]) {
    let committed = match committed_files(repo) {
        Some(c) => c,
        None => return, // not a git repo / git unavailable: degrade gracefully
    };
    for f in findings.iter_mut().filter(|f| is_secret(f)) {
        let file = match &f.location {
            Some(loc) => repo_relative(repo, &loc.file),
            None => repo_relative(repo, &f.url),
        };
        let is_committed = committed.contains(&file);
        let label = if is_committed {
            "committed"
        } else {
            "working-tree-only"
        };
        f.title = format!("{} [{label}]", f.title);
        f.description = format!("{} (secret is {label} in git)", f.description);
        if is_committed {
            f.severity = bump(f.severity.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command;

    fn git(dir: &Path, args: &[&str]) {
        let ok = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("run git")
            .status
            .success();
        assert!(ok, "git {args:?} failed");
    }

    fn secret_in(file: &str, line: u32) -> Finding {
        Finding::new(
            "Possible secret (aws)",
            Severity::High,
            "u",
            "d",
            "s",
            "sast/secrets",
        )
        .with_location(crate::types::CodeLocation {
            file: file.to_string(),
            line_start: line,
            line_end: None,
        })
    }

    #[test]
    fn labels_committed_vs_working_tree() {
        let tmp = std::env::temp_dir().join(format!("rz-git-{}", crate::types::uuid_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        git(&tmp, &["init", "-q"]);
        git(&tmp, &["config", "user.email", "t@t"]);
        git(&tmp, &["config", "user.name", "t"]);
        std::fs::write(tmp.join("config.yaml"), "aws: AKIAABCDEFGHIJKLMNOP\n").unwrap();
        git(&tmp, &["add", "config.yaml"]);
        git(&tmp, &["commit", "-q", "-m", "init"]);
        // Untracked working-tree file.
        std::fs::write(tmp.join(".env"), "SECRET=AKIAABCDEFGHIJKLMNOP\n").unwrap();

        let mut findings = vec![secret_in("config.yaml", 1), secret_in(".env", 1)];
        label_secrets(&tmp, &mut findings);

        let committed = findings
            .iter()
            .find(|f| f.title.contains("config.yaml") || f.title.contains("[committed]"))
            .unwrap();
        assert!(committed.title.contains("[committed]"));
        assert_eq!(
            committed.severity,
            Severity::Critical,
            "committed bumps High->Critical"
        );

        let wt = findings
            .iter()
            .find(|f| f.title.contains("[working-tree-only]"))
            .unwrap();
        assert_eq!(wt.severity, Severity::High, "working-tree keeps severity");

        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn non_git_dir_leaves_findings_untouched() {
        let tmp = std::env::temp_dir().join(format!("rz-nogit-{}", crate::types::uuid_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        let mut findings = vec![secret_in("config.yaml", 1)];
        label_secrets(&tmp, &mut findings);
        assert_eq!(findings[0].title, "Possible secret (aws)");
        assert_eq!(findings[0].severity, Severity::High);
        std::fs::remove_dir_all(&tmp).ok();
    }

    #[test]
    fn non_secret_findings_are_not_labeled() {
        let tmp = std::env::temp_dir().join(format!("rz-git2-{}", crate::types::uuid_v4()));
        std::fs::create_dir_all(&tmp).unwrap();
        git(&tmp, &["init", "-q"]);
        let mut f = vec![Finding::new(
            "XSS",
            Severity::High,
            "u",
            "d",
            "s",
            "active/xss",
        )];
        label_secrets(&tmp, &mut f);
        assert_eq!(f[0].title, "XSS");
        std::fs::remove_dir_all(&tmp).ok();
    }
}
