//! Autonomous Auto-Fix & Remediation PR Engine (Strix-inspired).
//!
//! Synthesizes secure source code patches and unified diffs directly from correlated
//! SAST/DAST evidence, preparing merge-ready pull request files.

use crate::types::Finding;
use anyhow::Result;
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
