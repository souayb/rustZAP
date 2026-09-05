//! Autonomous Auto-Fix & Remediation PR Engine (Strix-inspired).
//!
//! Synthesizes secure source code patches and unified diffs directly from correlated
//! SAST/DAST evidence, preparing merge-ready pull request files.

use crate::types::Finding;
use anyhow::{Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Build a structured remediation prompt for an LLM to generate a secure fix.
pub fn generate_patch_prompt(finding: &Finding, file_path: &str, code_content: &str) -> String {
    format!(
        r#"You are a principal security engineer and senior software developer.
Fix the following security vulnerability in {file_path}.

VULNERABILITY DETAILS:
- Title: {title}
- Plugin: {plugin}
- Severity: {severity:?}
- Description: {description}
- Solution Guideline: {solution}

SOURCE CODE ({file_path}):
```
{code_content}
```

INSTRUCTIONS:
1. Provide the complete patched version of the file or a unified git diff.
2. Ensure you follow secure coding best practices (e.g. parameterization, sanitization, strict validation).
3. Do not alter unrelated logic or remove comments.
"#,
        file_path = file_path,
        title = finding.title,
        plugin = finding.plugin,
        severity = finding.severity,
        description = finding.description,
        solution = finding.solution,
        code_content = code_content,
    )
}

/// Generate a basic unified git diff representation.
pub fn generate_unified_diff(file_path: &str, original_code: &str, patched_code: &str) -> String {
    format!(
        "--- a/{file_path}\n+++ b/{file_path}\n@@ -1,{orig_len} +1,{patch_len} @@\n{diff}",
        file_path = file_path,
        orig_len = original_code.lines().count(),
        patch_len = patched_code.lines().count(),
        diff = compute_simple_diff(original_code, patched_code)
    )
}

fn compute_simple_diff(original: &str, patched: &str) -> String {
    let orig_lines: Vec<&str> = original.lines().collect();
    let patch_lines: Vec<&str> = patched.lines().collect();
    let mut out = Vec::new();

    let mut i = 0;
    let mut j = 0;

    while i < orig_lines.len() || j < patch_lines.len() {
        if i < orig_lines.len() && j < patch_lines.len() {
            if orig_lines[i] == patch_lines[j] {
                out.push(format!(" {}", orig_lines[i]));
                i += 1;
                j += 1;
            } else {
                out.push(format!("-{}", orig_lines[i]));
                out.push(format!("+{}", patch_lines[j]));
                i += 1;
                j += 1;
            }
        } else if i < orig_lines.len() {
            out.push(format!("-{}", orig_lines[i]));
            i += 1;
        } else {
            out.push(format!("+{}", patch_lines[j]));
            j += 1;
        }
    }

    out.join("\n")
}

/// Save a generated patch to a target output directory.
pub fn save_patch_file(
    finding_id: &str,
    patch_content: &str,
    output_dir: &Path,
) -> Result<PathBuf> {
    if !output_dir.exists() {
        fs::create_dir_all(output_dir)?;
    }
    let patch_path = output_dir.join(format!("{finding_id}.patch"));
    fs::write(&patch_path, patch_content)?;
    Ok(patch_path)
}

/// Export remediation prompt files for findings that have a `location`.
/// Writes `{id}.md` under `out_dir`. Returns paths written.
pub fn export_findings(
    findings: &[Finding],
    out_dir: impl AsRef<Path>,
    only_ids: Option<&[String]>,
) -> Result<Vec<String>> {
    let out_dir = out_dir.as_ref();
    fs::create_dir_all(out_dir)
        .with_context(|| format!("create autofix dir {}", out_dir.display()))?;
    let mut written = Vec::new();
    for f in findings {
        if let Some(ids) = only_ids {
            if !ids.iter().any(|id| id == &f.id) {
                continue;
            }
        }
        let Some(loc) = f.location.as_ref() else {
            continue;
        };
        let path = &loc.file;
        let code = fs::read_to_string(path).unwrap_or_else(|_| {
            format!(
                "// (source unavailable at export time — path was {path})\n\
                 // Apply the solution guideline from the finding manually.\n"
            )
        });
        let prompt = generate_patch_prompt(f, path, &code);
        let file_path = out_dir.join(format!("{}.md", f.id));
        fs::write(&file_path, prompt)?;
        written.push(file_path.display().to_string());
    }
    Ok(written)
}

/// Load a rustzap JSON report and export autofix prompts for findings with locations.
pub fn export_from_report(report_path: &str, out_dir: &str) -> Result<Vec<String>> {
    let raw =
        fs::read_to_string(report_path).with_context(|| format!("read report {report_path}"))?;
    let report: crate::report::Report =
        serde_json::from_str(&raw).with_context(|| format!("parse report JSON {report_path}"))?;
    export_findings(&report.findings, out_dir, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{CodeLocation, Severity};

    #[test]
    fn test_unified_diff_generation() {
        let orig = "fn main() {\n    let q = format!(\"SELECT * FROM u WHERE id={}\", id);\n}";
        let patch = "fn main() {\n    let q = \"SELECT * FROM u WHERE id = $1\";\n}";
        let diff = generate_unified_diff("src/main.rs", orig, patch);
        assert!(diff.contains("--- a/src/main.rs"));
        assert!(diff.contains("+++ b/src/main.rs"));
        assert!(diff.contains("-    let q = format!(\"SELECT * FROM u WHERE id={}\", id);"));
        assert!(diff.contains("+    let q = \"SELECT * FROM u WHERE id = $1\";"));
    }

    #[test]
    fn export_findings_writes_prompt_for_located() {
        let dir = std::env::temp_dir().join(format!("rz-autofix-{}", crate::types::uuid_v4()));
        let src = dir.join("vuln.rs");
        fs::create_dir_all(&dir).unwrap();
        fs::write(&src, "fn bad() { let _ = 1; }\n").unwrap();
        let f = Finding::new("t", Severity::High, "http://x", "d", "s", "sast/x").with_location(
            CodeLocation {
                file: src.display().to_string(),
                line_start: 1,
                line_end: None,
            },
        );
        let out = dir.join("patches");
        let written = export_findings(&[f], &out, None).unwrap();
        assert_eq!(written.len(), 1);
        let body = fs::read_to_string(&written[0]).unwrap();
        assert!(body.contains("principal security engineer"));
        assert!(body.contains("fn bad()"));
        let _ = fs::remove_dir_all(&dir);
    }
}
