//! HTML / template form extraction → findings + attack-plan entries.

use std::path::{Path, PathBuf};

use regex::Regex;
use scraper::{Html, Selector};

use crate::analyze::inventory::{
    file_url, is_html_like, line_number, read_text_head, rel_path, MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::report::AttackPlanEntry;
use crate::types::{CodeLocation, Confidence, Finding, Severity};

const MAX_FORM_FINDINGS: usize = 60;

pub struct FormScanResult {
    pub findings: Vec<Finding>,
    pub attack_plan: Vec<AttackPlanEntry>,
}

pub fn scan(root: &Path, files: &[PathBuf]) -> FormScanResult {
    let mut findings = Vec::new();
    let mut attack_plan = Vec::new();
    for path in files {
        if !is_html_like(path) {
            continue;
        }
        let Some((src, _truncated)) = read_text_head(path, MAX_SOURCE_BYTES) else {
            continue;
        };
        let extracted = extract_forms(&src);
        let rel = rel_path(root, path);
        for form in extracted {
            if findings.len() >= MAX_FORM_FINDINGS {
                break;
            }
            let line = line_number(&src, form.offset);
            let severity = form_severity(&form);
            let title = format!("HTML form {} {}", form.method, form.action);
            findings.push(
                Finding::new(
                    title,
                    severity,
                    file_url(path, Some(line)),
                    format!(
                        "Form in {rel} action=`{}` method={} params=[{}].",
                        form.action,
                        form.method,
                        form.params.join(", ")
                    ),
                    "Review authentication, CSRF, and file-upload handling on this endpoint.",
                    "sast/forms",
                )
                .with_source_tool(SOURCE_TOOL)
                .with_parameter(form.action.clone())
                .with_evidence(format!("{} {} ({})", form.method, form.action, form.reason))
                .with_location(CodeLocation {
                    file: rel.clone(),
                    line_start: line,
                    line_end: None,
                })
                .with_confidence(Confidence::Firm),
            );
            attack_plan.push(AttackPlanEntry {
                url: form.action.clone(),
                method: form.method.clone(),
                params: form.params.clone(),
                reason: form.reason.clone(),
            });
        }
    }
    FormScanResult {
        findings,
        attack_plan,
    }
}

struct ParsedForm {
    action: String,
    method: String,
    params: Vec<String>,
    types: Vec<String>,
    reason: String,
    offset: usize,
}

fn extract_forms(src: &str) -> Vec<ParsedForm> {
    let mut out = extract_with_scraper(src);
    if out.is_empty() {
        out = extract_with_regex(src);
    }
    out
}

fn extract_with_scraper(src: &str) -> Vec<ParsedForm> {
    let document = Html::parse_document(src);
    let Ok(form_sel) = Selector::parse("form") else {
        return Vec::new();
    };
    let Ok(input_sel) = Selector::parse("input, select, textarea") else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for form in document.select(&form_sel) {
        let action = form.value().attr("action").unwrap_or("").trim().to_string();
        let action = if action.is_empty() {
            "/".to_string()
        } else {
            action
        };
        let method = form.value().attr("method").unwrap_or("GET").to_uppercase();
        let mut params = Vec::new();
        let mut types = Vec::new();
        for input in form.select(&input_sel) {
            if let Some(name) = input.value().attr("name") {
                if !params.iter().any(|p: &String| p == name) {
                    params.push(name.to_string());
                }
            }
            if let Some(t) = input.value().attr("type") {
                types.push(t.to_string());
            }
        }
        let reason = form_reason(&types, &params);
        let offset = src.to_ascii_lowercase().find("<form").unwrap_or(0);
        // Prefer the Nth <form occurrence matching this index.
        let nth = out.len();
        let offset = nth_form_offset(src, nth).unwrap_or(offset);
        out.push(ParsedForm {
            action,
            method,
            params,
            types,
            reason,
            offset,
        });
    }
    out
}

fn nth_form_offset(src: &str, n: usize) -> Option<usize> {
    let lower = src.to_ascii_lowercase();
    let mut from = 0;
    let mut seen = 0usize;
    while let Some(i) = lower[from..].find("<form") {
        let abs = from + i;
        if seen == n {
            return Some(abs);
        }
        seen += 1;
        from = abs + 5;
    }
    None
}

fn extract_with_regex(src: &str) -> Vec<ParsedForm> {
    let form_re = Regex::new(r"(?is)<form\b([^>]*)>(.*?)</form>").expect("form regex");
    let attr_action = Regex::new(r#"(?i)action\s*=\s*['"]([^'"]*)['"]"#).expect("action attr");
    let attr_method = Regex::new(r#"(?i)method\s*=\s*['"]([^'"]*)['"]"#).expect("method attr");
    let input_re = Regex::new(r#"(?is)<input\b([^>]*)>"#).expect("input regex");
    let name_re = Regex::new(r#"(?i)name\s*=\s*['"]([^'"]+)['"]"#).expect("name attr");
    let type_re = Regex::new(r#"(?i)type\s*=\s*['"]([^'"]+)['"]"#).expect("type attr");

    let mut out = Vec::new();
    for cap in form_re.captures_iter(src) {
        let attrs = cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let body = cap.get(2).map(|m| m.as_str()).unwrap_or("");
        let action = attr_action
            .captures(attrs)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "/".to_string());
        let method = attr_method
            .captures(attrs)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_uppercase()))
            .unwrap_or_else(|| "GET".to_string());
        let mut params = Vec::new();
        let mut types = Vec::new();
        for ic in input_re.captures_iter(body) {
            let iattrs = ic.get(1).map(|m| m.as_str()).unwrap_or("");
            if let Some(n) = name_re
                .captures(iattrs)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            {
                if !params.contains(&n) {
                    params.push(n);
                }
            }
            if let Some(t) = type_re
                .captures(iattrs)
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
            {
                types.push(t);
            }
        }
        let reason = form_reason(&types, &params);
        let offset = cap.get(0).map(|m| m.start()).unwrap_or(0);
        out.push(ParsedForm {
            action,
            method,
            params,
            types,
            reason,
            offset,
        });
    }
    out
}

fn form_reason(types: &[String], names: &[String]) -> String {
    let has_password = types.iter().any(|t| t.eq_ignore_ascii_case("password"));
    let has_file = types.iter().any(|t| t.eq_ignore_ascii_case("file"));
    let has_csrf = names.iter().any(|n| {
        let l = n.to_ascii_lowercase();
        l.contains("csrf") || l.ends_with("_token") || l == "authenticity_token"
    });
    if has_password {
        "form+password".to_string()
    } else if has_file {
        "form+file".to_string()
    } else if has_csrf {
        "form+csrf".to_string()
    } else {
        "form".to_string()
    }
}

fn form_severity(form: &ParsedForm) -> Severity {
    if form
        .types
        .iter()
        .any(|t| t.eq_ignore_ascii_case("password"))
    {
        Severity::Medium
    } else if form.types.iter().any(|t| t.eq_ignore_ascii_case("file")) {
        Severity::Low
    } else {
        Severity::Info
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_login_form_password_and_csrf() {
        let html = r#"
            <form action="/login" method="POST" enctype="application/x-www-form-urlencoded">
              <input type="text" name="user">
              <input type="password" name="pass">
              <input type="hidden" name="csrf_token" value="fake">
            </form>
        "#;
        let forms = extract_forms(html);
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].action, "/login");
        assert_eq!(forms[0].method, "POST");
        assert!(forms[0].params.contains(&"user".to_string()));
        assert!(forms[0].params.contains(&"pass".to_string()));
        assert_eq!(forms[0].reason, "form+password");
    }

    #[test]
    fn regex_fallback_on_jinja_ish_markup() {
        let html = r#"<form action="{{ url }}" method="get"><input name="q" type="text"></form>"#;
        let forms = extract_forms(html);
        assert!(!forms.is_empty());
        assert!(forms[0].params.contains(&"q".to_string()));
    }
}
