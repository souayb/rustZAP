//! Lightweight `.gitignore` / `.rustzapignore` matching for the native repo walk.
//!
//! Intentionally not the `ignore` crate: we only need root + nested ignore files,
//! `*` / `**` / `?`, directory-only trailing `/`, and `!` negation.

use std::path::Path;

use regex::Regex;

#[derive(Clone)]
struct IgnoreRule {
    negated: bool,
    dir_only: bool,
    re: Regex,
}

#[derive(Clone)]
struct IgnoreFile {
    /// Directory containing this ignore file, relative to the repo root (`""` = root).
    base: String,
    rules: Vec<IgnoreRule>,
}

#[derive(Clone, Default)]
pub struct IgnoreSet {
    files: Vec<IgnoreFile>,
}

impl IgnoreSet {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_rules(&mut self, base: &str, text: &str) {
        let rules = parse_rules(text);
        if rules.is_empty() {
            return;
        }
        self.files.push(IgnoreFile {
            base: normalize_rel(base),
            rules,
        });
    }

    pub fn load_file(&mut self, base: &str, path: &Path) {
        let Ok(text) = std::fs::read_to_string(path) else {
            return;
        };
        self.add_rules(base, &text);
    }

    /// Whether `rel` (repo-relative, `/`-separated) should be skipped.
    pub fn is_ignored(&self, rel: &str, is_dir: bool) -> bool {
        let parts: Vec<&str> = rel.split('/').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return false;
        }
        let mut acc = String::new();
        for (i, part) in parts.iter().enumerate() {
            if !acc.is_empty() {
                acc.push('/');
            }
            acc.push_str(part);
            let last = i + 1 == parts.len();
            if last {
                return self.match_path(&acc, is_dir);
            }
            if self.match_path(&acc, true) {
                return true;
            }
        }
        false
    }

    fn match_path(&self, rel: &str, is_dir: bool) -> bool {
        let mut ignored = false;
        for file in &self.files {
            let Some(local) = strip_base(rel, &file.base) else {
                continue;
            };
            if local.is_empty() {
                continue;
            }
            for rule in &file.rules {
                if rule.dir_only && !is_dir {
                    continue;
                }
                if rule.re.is_match(local) {
                    ignored = !rule.negated;
                }
            }
        }
        ignored
    }
}

fn strip_base<'a>(rel: &'a str, base: &str) -> Option<&'a str> {
    if base.is_empty() {
        return Some(rel);
    }
    if rel == base {
        return Some("");
    }
    rel.strip_prefix(base)
        .and_then(|rest| rest.strip_prefix('/'))
}

fn normalize_rel(s: &str) -> String {
    s.replace('\\', "/").trim_matches('/').to_string()
}

fn parse_rules(text: &str) -> Vec<IgnoreRule> {
    let mut rules = Vec::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (negated, rest) = match line.strip_prefix('!') {
            Some(s) => (true, s.trim()),
            None => (false, line),
        };
        if rest.is_empty() {
            continue;
        }
        let dir_only = rest.ends_with('/');
        let pat = rest.trim_end_matches('/');
        if pat.is_empty() {
            continue;
        }
        match glob_to_regex(pat) {
            Ok(re) => rules.push(IgnoreRule {
                negated,
                dir_only,
                re,
            }),
            Err(_) => {
                tracing::debug!(pattern = pat, "skipping invalid gitignore glob");
            }
        }
    }
    rules
}

/// Convert a gitignore glob to a regex matching a path relative to the ignore file.
fn glob_to_regex(pattern: &str) -> Result<Regex, regex::Error> {
    let leading_slash = pattern.starts_with('/');
    let pattern = pattern.trim_start_matches('/');
    let anchored = leading_slash || pattern.contains('/');

    let mut out = String::from("^");
    if !anchored {
        out.push_str("(?:.*/)?");
    }

    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => {
                if i + 1 < chars.len() && chars[i + 1] == '*' {
                    i += 1;
                    if i + 1 < chars.len() && chars[i + 1] == '/' {
                        out.push_str("(?:.*/)?");
                        i += 1;
                    } else {
                        out.push_str(".*");
                    }
                } else {
                    out.push_str("[^/]*");
                }
            }
            '?' => out.push_str("[^/]"),
            c @ ('.' | '+' | '(' | ')' | '|' | '^' | '$' | '{' | '}' | '[' | ']' | '\\') => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
        i += 1;
    }
    out.push('$');
    Regex::new(&out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dir_pattern_ignores_directory_and_children() {
        let mut set = IgnoreSet::new();
        set.add_rules("", "ignored_dir/\n");
        assert!(set.is_ignored("ignored_dir", true));
        assert!(set.is_ignored("ignored_dir/secret.js", false));
        assert!(!set.is_ignored("src/ok.js", false));
    }

    #[test]
    fn star_glob_and_negation() {
        let mut set = IgnoreSet::new();
        set.add_rules("", "*.tmp\n!keep.tmp\n");
        assert!(set.is_ignored("foo.tmp", false));
        assert!(set.is_ignored("sub/a.tmp", false));
        assert!(!set.is_ignored("keep.tmp", false));
        assert!(!set.is_ignored("keep.js", false));
    }

    #[test]
    fn nested_gitignore_is_relative_to_its_dir() {
        let mut set = IgnoreSet::new();
        set.add_rules("pkg", "build/\n");
        assert!(set.is_ignored("pkg/build", true));
        assert!(set.is_ignored("pkg/build/out.js", false));
        assert!(!set.is_ignored("build", true));
    }

    #[test]
    fn comments_and_blank_lines_ignored() {
        let mut set = IgnoreSet::new();
        set.add_rules("", "# comment\n\n  \nvendor/\n");
        assert!(set.is_ignored("vendor", true));
    }
}
