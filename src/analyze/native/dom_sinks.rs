//! DOM XSS + Argus-style JS sinks (`document.cookie`, web storage, `postMessage`).

use std::path::{Path, PathBuf};

use regex::Regex;

use crate::analyze::inventory::{
    file_url, is_js_like, is_minified_name, line_number, read_text_capped, rel_path,
    MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::types::{CodeLocation, Finding, Severity};

const MAX_SINK_FINDINGS: usize = 80;

pub const PLUGIN_DOM: &str = "sast/dom-sinks";
pub const PLUGIN_COOKIES: &str = "sast/js-cookies";
pub const PLUGIN_STORAGE: &str = "sast/js-storage";
pub const PLUGIN_POSTMESSAGE: &str = "sast/js-postmessage";

struct SinkPat {
    id: &'static str,
    plugin: &'static str,
    cwe: u32,
    owasp: &'static str,
    solution: &'static str,
    re: Regex,
}

fn patterns() -> Vec<SinkPat> {
    [
        (
            "innerHTML",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r"\.innerHTML\b",
        ),
        (
            "outerHTML",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r"\.outerHTML\b",
        ),
        (
            "document.write",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r"document\.write(ln)?\s*\(",
        ),
        (
            "eval",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r"\beval\s*\(",
        ),
        (
            "Function",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r"\bnew\s+Function\s*\(",
        ),
        (
            "setTimeout-string",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r#"setTimeout\s*\(\s*['"]"#,
        ),
        (
            "setInterval-string",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r#"setInterval\s*\(\s*['"]"#,
        ),
        (
            "location.href",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r"\blocation\.(href|assign|replace)\b",
        ),
        (
            "insertAdjacentHTML",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r"insertAdjacentHTML\s*\(",
        ),
        (
            "dangerouslySetInnerHTML",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r"dangerouslySetInnerHTML",
        ),
        (
            "javascript-url",
            PLUGIN_DOM,
            79,
            "A03:2021",
            "Avoid assigning untrusted data to HTML/JS sinks; use textContent or sanitization.",
            r#"['"]javascript:"#,
        ),
        (
            "document.cookie-assign",
            PLUGIN_COOKIES,
            565,
            "A05:2021",
            "Do not write untrusted data into cookies; set HttpOnly, Secure, and SameSite.",
            r"document\.cookie\s*[+]?=",
        ),
        (
            "document.cookie",
            PLUGIN_COOKIES,
            565,
            "A05:2021",
            "Treat cookie values as untrusted; prefer HttpOnly cookies that scripts cannot read.",
            r"document\.cookie\b",
        ),
        (
            "localStorage.setItem",
            PLUGIN_STORAGE,
            922,
            "A04:2021",
            "Do not store secrets in localStorage; it is readable by any script on the origin.",
            r"localStorage\s*\.\s*setItem\s*\(",
        ),
        (
            "sessionStorage.setItem",
            PLUGIN_STORAGE,
            922,
            "A04:2021",
            "Do not store secrets in sessionStorage; it is readable by any script on the origin.",
            r"sessionStorage\s*\.\s*setItem\s*\(",
        ),
        (
            "localStorage-assign",
            PLUGIN_STORAGE,
            922,
            "A04:2021",
            "Do not store secrets in localStorage; it is readable by any script on the origin.",
            r"localStorage\s*(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])\s*=",
        ),
        (
            "sessionStorage-assign",
            PLUGIN_STORAGE,
            922,
            "A04:2021",
            "Do not store secrets in sessionStorage; it is readable by any script on the origin.",
            r"sessionStorage\s*(?:\.[A-Za-z_$][\w$]*|\[[^\]]+\])\s*=",
        ),
        (
            "postMessage",
            PLUGIN_POSTMESSAGE,
            346,
            "A08:2021",
            "Pass an explicit target origin (not `*`) and validate `event.origin` on receive.",
            r"\b(?:window\.)?postMessage\s*\(",
        ),
    ]
    .into_iter()
    .map(|(id, plugin, cwe, owasp, solution, pat)| SinkPat {
        id,
        plugin,
        cwe,
        owasp,
        solution,
        re: Regex::new(pat).expect("static sink regex"),
    })
    .collect()
}

pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let pats = patterns();
    let mut out = Vec::new();
    for path in files {
        if !is_js_like(path) || is_minified_name(path) {
            continue;
        }
        let Some(src) = read_text_capped(path, MAX_SOURCE_BYTES) else {
            continue;
        };
        out.extend(scan_source(root, path, &src, &pats));
        if out.len() >= MAX_SINK_FINDINGS {
            break;
        }
    }
    out.truncate(MAX_SINK_FINDINGS);
    out
}

fn scan_source(root: &Path, path: &Path, src: &str, pats: &[SinkPat]) -> Vec<Finding> {
    let rel = rel_path(root, path);
    let mut out = Vec::new();
    for pat in pats {
        for m in pat.re.find_iter(src) {
            if pat.id == "document.cookie" && cookie_is_assignment(src, m.end()) {
                continue;
            }
            if out.len() >= MAX_SINK_FINDINGS {
                break;
            }
            let line = line_number(src, m.start());
            let snippet = snippet_at(src, m.start(), 80);
            out.push(
                Finding::new(
                    format!("JS sink ({})", pat.id),
                    Severity::Medium,
                    file_url(path, Some(line)),
                    format!("Potential sink `{}` in {rel}.", pat.id),
                    pat.solution,
                    pat.plugin,
                )
                .with_source_tool(SOURCE_TOOL)
                .with_parameter(pat.id)
                .with_evidence(snippet)
                .with_cwe(pat.cwe)
                .with_owasp(pat.owasp)
                .with_location(CodeLocation {
                    file: rel.clone(),
                    line_start: line,
                    line_end: None,
                })
                .tentative(),
            );
        }
    }
    out
}

fn cookie_is_assignment(src: &str, match_end: usize) -> bool {
    let rest = src.get(match_end..).unwrap_or("").trim_start();
    rest.starts_with("+=") || rest.starts_with('=')
}

fn snippet_at(src: &str, start: usize, max: usize) -> String {
    let line_start = src[..start].rfind('\n').map(|i| i + 1).unwrap_or(0);
    let line_end = src[start..]
        .find('\n')
        .map(|i| start + i)
        .unwrap_or(src.len());
    let line = src[line_start..line_end].trim();
    if line.len() > max {
        format!("{}…", &line[..max])
    } else {
        line.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flags_innerhtml_and_dangerously_set() {
        let src = r#"
            el.innerHTML = user;
            const x = { dangerouslySetInnerHTML: { __html: t } };
        "#;
        let findings = scan_source(Path::new("."), Path::new("app.js"), src, &patterns());
        assert!(findings
            .iter()
            .any(|f| f.parameter.as_deref() == Some("innerHTML")));
        assert!(findings
            .iter()
            .any(|f| f.parameter.as_deref() == Some("dangerouslySetInnerHTML")));
        assert!(findings.iter().all(|f| f.plugin == PLUGIN_DOM));
    }

    #[test]
    fn flags_eval_and_document_write() {
        let src = "eval(q); document.write(html);";
        let findings = scan_source(Path::new("."), Path::new("a.js"), src, &patterns());
        assert!(findings
            .iter()
            .any(|f| f.parameter.as_deref() == Some("eval")));
        assert!(findings
            .iter()
            .any(|f| f.parameter.as_deref() == Some("document.write")));
    }

    #[test]
    fn flags_cookie_storage_and_postmessage() {
        let src = r#"
            document.cookie = "session=" + location.hash;
            const c = document.cookie;
            localStorage.setItem("token", userInput);
            sessionStorage.theme = theme;
            window.postMessage(payload, "*");
        "#;
        let findings = scan_source(Path::new("."), Path::new("app.js"), src, &patterns());
        assert!(findings.iter().any(|f| {
            f.plugin == PLUGIN_COOKIES && f.parameter.as_deref() == Some("document.cookie-assign")
        }));
        assert!(findings.iter().any(|f| {
            f.plugin == PLUGIN_COOKIES && f.parameter.as_deref() == Some("document.cookie")
        }));
        assert!(findings.iter().any(|f| {
            f.plugin == PLUGIN_STORAGE && f.parameter.as_deref() == Some("localStorage.setItem")
        }));
        assert!(findings.iter().any(|f| {
            f.plugin == PLUGIN_STORAGE && f.parameter.as_deref() == Some("sessionStorage-assign")
        }));
        assert!(findings.iter().any(
            |f| f.plugin == PLUGIN_POSTMESSAGE && f.parameter.as_deref() == Some("postMessage")
        ));
    }

    #[test]
    fn cookie_assign_does_not_double_count_as_access() {
        let src = r#"document.cookie = "a=1";"#;
        let findings = scan_source(Path::new("."), Path::new("a.js"), src, &patterns());
        let cookies: Vec<_> = findings
            .iter()
            .filter(|f| f.plugin == PLUGIN_COOKIES)
            .collect();
        assert_eq!(cookies.len(), 1);
        assert_eq!(
            cookies[0].parameter.as_deref(),
            Some("document.cookie-assign")
        );
    }
}
