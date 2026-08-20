//! Mine query/body parameter names from common web-framework source patterns.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::analyze::inventory::{
    file_url, is_param_source, line_number, read_text_head, rel_path, MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::report::AttackPlanEntry;
use crate::types::{CodeLocation, Finding, Severity};

const MAX_PARAM_FINDINGS: usize = 80;

pub struct ParamScanResult {
    pub findings: Vec<Finding>,
    pub attack_plan: Vec<AttackPlanEntry>,
}

struct ParamPat {
    id: &'static str,
    method_hint: &'static str,
    re: Regex,
    /// Capture group index for the parameter name.
    name_group: usize,
}

fn patterns() -> Vec<ParamPat> {
    [
        (
            "req.query",
            "GET",
            r"req\.query\.([A-Za-z_][A-Za-z0-9_]*)",
            1,
        ),
        (
            "req.params",
            "GET",
            r"req\.params\.([A-Za-z_][A-Za-z0-9_]*)",
            1,
        ),
        (
            "req.body",
            "POST",
            r"req\.body\.([A-Za-z_][A-Za-z0-9_]*)",
            1,
        ),
        (
            "request.args",
            "GET",
            r#"request\.args\.get\(\s*['"]([^'"]+)['"]"#,
            1,
        ),
        (
            "request.form",
            "POST",
            r#"request\.form\.get\(\s*['"]([^'"]+)['"]"#,
            1,
        ),
        (
            "request.GET",
            "GET",
            r#"request\.GET(?:\.get)?\(\s*['"]([^'"]+)['"]"#,
            1,
        ),
        (
            "RequestParam",
            "GET",
            r#"@RequestParam\s*\(\s*(?:value\s*=\s*)?['"]([^'"]+)['"]"#,
            1,
        ),
        (
            "params-symbol",
            "GET",
            r"params\[:([A-Za-z_][A-Za-z0-9_]*)\]",
            1,
        ),
        ("c.query", "GET", r#"\bc\.query\(\s*['"]([^'"]+)['"]"#, 1),
        ("php-get", "GET", r#"\$_GET\s*\[\s*['"]([^'"]+)['"]"#, 1),
        ("php-post", "POST", r#"\$_POST\s*\[\s*['"]([^'"]+)['"]"#, 1),
        (
            "getParameter",
            "GET",
            r#"getParameter\(\s*['"]([^'"]+)['"]"#,
            1,
        ),
    ]
    .into_iter()
    .map(|(id, method_hint, pat, name_group)| ParamPat {
        id,
        method_hint,
        re: Regex::new(pat).expect("static params regex"),
        name_group,
    })
    .collect()
}

pub fn scan(root: &Path, files: &[PathBuf]) -> ParamScanResult {
    let pats = patterns();
    let mut findings = Vec::new();
    let mut attack_plan = Vec::new();
    // Group params per (rel file, method) for the attack plan.
    let mut plan_keys: Vec<(String, String, BTreeSet<String>, String)> = Vec::new();

    for path in files {
        if !is_param_source(path) {
            continue;
        }
        let Some((src, _truncated)) = read_text_head(path, MAX_SOURCE_BYTES) else {
            continue;
        };
        let rel = rel_path(root, path);
        let hits = scan_source(path, &rel, &src, &pats);
        for (finding, name, method, kind) in hits {
            if findings.len() >= MAX_PARAM_FINDINGS {
                break;
            }
            findings.push(finding);
            let key = (rel.clone(), method.to_string());
            if let Some(slot) = plan_keys
                .iter_mut()
                .find(|(u, m, _, _)| u == &key.0 && m == &key.1)
            {
                slot.2.insert(name);
                if !slot.3.contains(kind) {
                    slot.3 = format!("{}; {}", slot.3, kind);
                }
            } else {
                let mut set = BTreeSet::new();
                set.insert(name);
                plan_keys.push((key.0, key.1, set, kind.to_string()));
            }
        }
        if findings.len() >= MAX_PARAM_FINDINGS {
            break;
        }
    }

    for (url, method, names, reason) in plan_keys {
        attack_plan.push(AttackPlanEntry {
            url,
            method,
            params: names.into_iter().collect(),
            reason: format!("param:{reason}"),
        });
    }

    ParamScanResult {
        findings,
        attack_plan,
    }
}

fn scan_source(
    path: &Path,
    rel: &str,
    src: &str,
    pats: &[ParamPat],
) -> Vec<(Finding, String, &'static str, &'static str)> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for pat in pats {
        for cap in pat.re.captures_iter(src) {
            let Some(name) = cap.get(pat.name_group).map(|m| m.as_str().to_string()) else {
                continue;
            };
            let start = cap.get(0).map(|m| m.start()).unwrap_or(0);
            if !seen.insert((pat.id, name.clone())) {
                continue;
            }
            let line = line_number(src, start);
            let finding = Finding::new(
                format!("Request parameter `{name}` ({})", pat.id),
                Severity::Info,
                file_url(path, Some(line)),
                format!("Parameter `{name}` read via `{}` in {rel}.", pat.id),
                "Include this parameter in DAST coverage (injection, authz, validation).",
                "sast/params",
            )
            .with_source_tool(SOURCE_TOOL)
            .with_parameter(name.clone())
            .with_evidence(
                cap.get(0)
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_default(),
            )
            .with_location(CodeLocation {
                file: rel.to_string(),
                line_start: line,
                line_end: None,
            })
            .tentative();
            out.push((finding, name, pat.method_hint, pat.id));
        }
    }
    out
}

/// Scan a source snippet (unit tests).
#[cfg(test)]
fn scan_source_for_test(src: &str) -> Vec<(String, String)> {
    let path = Path::new("views.py");
    scan_source(path, "views.py", src, &patterns())
        .into_iter()
        .map(|(_, name, _, kind)| (name, kind.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mines_flask_and_express_params() {
        let py = r#"
            q = request.args.get("q")
            user = request.form.get("user")
        "#;
        let js = r#"
            const x = req.query.foo;
            const y = req.params.id;
            const z = req.body.email;
        "#;
        let py_hits = scan_source_for_test(py);
        assert!(py_hits.iter().any(|(n, k)| n == "q" && k == "request.args"));
        assert!(py_hits
            .iter()
            .any(|(n, k)| n == "user" && k == "request.form"));
        let js_hits = scan_source(Path::new("a.js"), "a.js", js, &patterns());
        let names: Vec<_> = js_hits.iter().map(|(_, n, _, _)| n.as_str()).collect();
        assert!(names.contains(&"foo"));
        assert!(names.contains(&"id"));
        assert!(names.contains(&"email"));
    }

    #[test]
    fn mines_php_and_rails() {
        let src = r#"
            $x = $_GET['page'];
            $y = $_POST['title'];
            id = params[:id]
        "#;
        let hits = scan_source_for_test(src);
        assert!(hits.iter().any(|(n, _)| n == "page"));
        assert!(hits.iter().any(|(n, _)| n == "title"));
        assert!(hits.iter().any(|(n, _)| n == "id"));
    }
}
