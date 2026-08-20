//! Repository inventory: languages, frameworks, and likely entrypoints.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::analyze::gitignore::IgnoreSet;
use crate::report::Inventory;
use crate::types::{CodeLocation, Finding, Severity};

pub(crate) const MAX_REPO_FILES: usize = 25_000;
pub(crate) const MAX_SOURCE_BYTES: u64 = 512 * 1024;
const MAX_ENTRYPOINTS: usize = 40;

/// Directories skipped by the repo walk: version-control internals and
/// generated / cache / dependency trees only.
///
/// This is an explicit blocklist — we intentionally do NOT skip every
/// dot-directory, because `.github/workflows`, `.circleci`, `.gitlab`, and
/// similar dot-config folders hold security-relevant files that must be walked.
const SKIP_DIRS: &[&str] = &[
    // Version control internals
    ".git",
    ".svn",
    ".hg",
    // JS / package trees
    "node_modules",
    "bower_components",
    ".pnpm-store",
    ".yarn",
    // Build / output
    "target",
    "dist",
    "build",
    "coverage",
    ".next",
    ".nuxt",
    ".svelte-kit",
    ".angular",
    ".parcel-cache",
    ".turbo",
    ".serverless",
    ".dart_tool",
    // Python
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    ".mypy_cache",
    ".pytest_cache",
    // Other language / tool caches
    "vendor",
    ".gradle",
    ".terraform",
    ".cargo",
    ".sass-cache",
    ".cache",
    // Editor / IDE
    ".idea",
    ".vscode",
    // Apple / mobile deps
    "Pods",
    "Carthage",
];

const ENTRYPOINT_NAMES: &[&str] = &[
    "main.rs",
    "app.py",
    "main.py",
    "wsgi.py",
    "asgi.py",
    "manage.py",
    "index.js",
    "server.js",
    "app.js",
    "index.ts",
    "server.ts",
    "main.go",
    "urls.py",
    "index.php",
    "program.cs",
    "application.java",
];

struct WalkFrame {
    dir: PathBuf,
    ignore: IgnoreSet,
}

/// Walk `root` (file or directory), skipping generated trees, `.gitignore`, and `.rustzapignore`.
pub fn collect_repo_files(root: &Path) -> Vec<PathBuf> {
    if root.is_file() {
        return vec![root.to_path_buf()];
    }
    let mut root_ignore = IgnoreSet::new();
    root_ignore.load_file("", &root.join(".gitignore"));
    root_ignore.load_file("", &root.join(".rustzapignore"));

    let mut out = Vec::new();
    let mut truncated = false;
    let mut stack = vec![WalkFrame {
        dir: root.to_path_buf(),
        ignore: root_ignore,
    }];
    while let Some(frame) = stack.pop() {
        let mut ignore = frame.ignore;
        if frame.dir != root {
            let base = rel_path(root, &frame.dir);
            ignore.load_file(&base, &frame.dir.join(".gitignore"));
            ignore.load_file(&base, &frame.dir.join(".rustzapignore"));
        }
        let entries = match fs::read_dir(&frame.dir) {
            Ok(e) => e,
            Err(_) => continue,
        };
        for entry in entries.flatten() {
            if out.len() >= MAX_REPO_FILES {
                truncated = true;
                break;
            }
            let path = entry.path();
            let Ok(meta) = entry.metadata() else {
                continue;
            };
            if meta.file_type().is_symlink() {
                continue;
            }
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            let rel = rel_path(root, &path);
            if meta.is_dir() {
                if should_skip_dir(&name_str) || ignore.is_ignored(&rel, true) {
                    continue;
                }
                stack.push(WalkFrame {
                    dir: path,
                    ignore: ignore.clone(),
                });
            } else if meta.is_file() {
                if ignore.is_ignored(&rel, false) {
                    continue;
                }
                out.push(path);
            }
        }
        if out.len() >= MAX_REPO_FILES {
            truncated = true;
            break;
        }
    }
    if truncated {
        let msg = format!(
            "rustzap: repo file cap of {MAX_REPO_FILES} reached under {}; \
             some files were NOT analyzed. Narrow the path or split the repo for full coverage.",
            root.display()
        );
        tracing::warn!("{msg}");
        eprintln!("{msg}");
    }
    out.sort();
    out
}

fn should_skip_dir(name: &str) -> bool {
    SKIP_DIRS.iter().any(|s| name.eq_ignore_ascii_case(s))
}

pub fn read_text_capped(path: &Path, max_bytes: u64) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if meta.len() > max_bytes {
        return None;
    }
    let bytes = fs::read(path).ok()?;
    if bytes.contains(&0) {
        return None;
    }
    String::from_utf8(bytes).ok()
}

pub fn rel_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_else(|_| path.to_string_lossy().replace('\\', "/"))
}

pub fn file_url(path: &Path, line: Option<u32>) -> String {
    match line {
        Some(l) if l > 0 => format!("file://{}#L{}", path.display(), l),
        _ => format!("file://{}", path.display()),
    }
}

pub fn line_number(text: &str, byte_offset: usize) -> u32 {
    let end = byte_offset.min(text.len());
    text.get(..end)
        .unwrap_or(text)
        .bytes()
        .filter(|b| *b == b'\n')
        .count() as u32
        + 1
}

pub fn extension_lower(path: &Path) -> Option<String> {
    path.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
}

pub fn is_minified_name(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.contains(".min."))
        .unwrap_or(false)
}

pub fn is_js_like(path: &Path) -> bool {
    matches!(
        extension_lower(path).as_deref(),
        Some("js" | "ts" | "tsx" | "jsx" | "vue" | "mjs" | "cjs")
    )
}

pub fn is_html_like(path: &Path) -> bool {
    matches!(
        extension_lower(path).as_deref(),
        Some("html" | "htm" | "jinja" | "j2" | "vue" | "jsx" | "tsx")
    )
}

pub fn is_param_source(path: &Path) -> bool {
    matches!(
        extension_lower(path).as_deref(),
        Some(
            "js" | "ts"
                | "tsx"
                | "jsx"
                | "py"
                | "java"
                | "rb"
                | "php"
                | "go"
                | "rs"
                | "cs"
                | "kt"
                | "vue"
        )
    )
}

/// Build inventory + a single info finding summarising it.
pub fn analyze(root: &Path, files: &[PathBuf]) -> (Inventory, Finding) {
    let mut languages = BTreeSet::new();
    let mut frameworks = BTreeSet::new();
    let mut entrypoints = Vec::new();

    for path in files {
        if let Some(lang) = language_for_path(path) {
            languages.insert(lang.to_string());
        }
        if is_entrypoint(path) && entrypoints.len() < MAX_ENTRYPOINTS {
            entrypoints.push(rel_path(root, path));
        }
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "package.json"
                | "cargo.toml"
                | "requirements.txt"
                | "pyproject.toml"
                | "go.mod"
                | "pom.xml"
                | "build.gradle"
                | "build.gradle.kts"
                | "gemfile"
                | "composer.json"
        ) {
            if let Some(text) = read_text_capped(path, MAX_SOURCE_BYTES) {
                for fw in frameworks_from_manifest(&name, &text) {
                    frameworks.insert(fw);
                }
            }
        }
    }

    let inventory = Inventory {
        languages: languages.into_iter().collect(),
        frameworks: frameworks.into_iter().collect(),
        entrypoints,
    };

    let finding = inventory_finding(root, files.len(), &inventory);
    (inventory, finding)
}

fn inventory_finding(root: &Path, scanned: usize, inventory: &Inventory) -> Finding {
    let langs = if inventory.languages.is_empty() {
        "none".to_string()
    } else {
        inventory.languages.join(", ")
    };
    let fws = if inventory.frameworks.is_empty() {
        "none".to_string()
    } else {
        inventory.frameworks.join(", ")
    };
    let desc = format!(
        "Scanned {scanned} files. Languages: {langs}. Frameworks: {fws}. Entrypoints: {}.",
        inventory.entrypoints.len()
    );
    Finding::new(
        "Repository inventory",
        Severity::Info,
        file_url(root, None),
        desc,
        "Use the inventory to prioritize SAST coverage and DAST starting points.",
        "sast/inventory",
    )
    .with_source_tool("rustzap-native")
    .with_location(CodeLocation {
        file: rel_path(root, root),
        line_start: 1,
        line_end: None,
    })
    .with_confidence(crate::types::Confidence::Firm)
}

fn language_for_path(path: &Path) -> Option<&'static str> {
    match extension_lower(path).as_deref()? {
        "rs" => Some("Rust"),
        "py" => Some("Python"),
        "js" | "mjs" | "cjs" | "jsx" => Some("JavaScript"),
        "ts" | "tsx" => Some("TypeScript"),
        "go" => Some("Go"),
        "java" => Some("Java"),
        "rb" => Some("Ruby"),
        "php" => Some("PHP"),
        "vue" => Some("Vue"),
        "cs" => Some("C#"),
        "kt" | "kts" => Some("Kotlin"),
        "swift" => Some("Swift"),
        "c" | "h" => Some("C"),
        "cpp" | "cc" | "cxx" | "hpp" => Some("C++"),
        "scala" => Some("Scala"),
        "html" | "htm" => Some("HTML"),
        "css" => Some("CSS"),
        "sh" | "bash" => Some("Shell"),
        _ => None,
    }
}

fn is_entrypoint(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .map(|n| ENTRYPOINT_NAMES.iter().any(|e| n.eq_ignore_ascii_case(e)))
        .unwrap_or(false)
}

fn frameworks_from_manifest(filename: &str, text: &str) -> Vec<String> {
    match filename {
        "package.json" => frameworks_from_package_json(text),
        "cargo.toml" => detect_needles(
            text,
            &[
                ("actix-web", "actix-web"),
                ("axum", "axum"),
                ("rocket", "rocket"),
                ("warp", "warp"),
            ],
        ),
        "requirements.txt" | "pyproject.toml" => detect_needles(
            text,
            &[
                ("django", "django"),
                ("flask", "flask"),
                ("fastapi", "fastapi"),
                ("celery", "celery"),
            ],
        ),
        "go.mod" => detect_needles(
            text,
            &[
                ("gin-gonic/gin", "gin"),
                ("labstack/echo", "echo"),
                ("gofiber/fiber", "fiber"),
                ("go-chi/chi", "chi"),
            ],
        ),
        "pom.xml" | "build.gradle" | "build.gradle.kts" => detect_needles(
            text,
            &[("spring-boot", "spring"), ("springframework", "spring")],
        ),
        "gemfile" => detect_needles(text, &[("rails", "rails"), ("sinatra", "sinatra")]),
        "composer.json" => detect_needles(
            text,
            &[("laravel/framework", "laravel"), ("symfony", "symfony")],
        ),
        _ => Vec::new(),
    }
}

fn frameworks_from_package_json(text: &str) -> Vec<String> {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut names = BTreeSet::new();
    for key in ["dependencies", "devDependencies", "peerDependencies"] {
        if let Some(map) = v.get(key).and_then(|x| x.as_object()) {
            for dep in map.keys() {
                if let Some(fw) = npm_framework(dep) {
                    names.insert(fw.to_string());
                }
            }
        }
    }
    names.into_iter().collect()
}

fn npm_framework(dep: &str) -> Option<&'static str> {
    let d = dep.to_ascii_lowercase();
    Some(match d.as_str() {
        "express" => "express",
        "@nestjs/core" | "nestjs" | "@nestjs/common" => "nest",
        "next" => "next",
        "vue" => "vue",
        "nuxt" => "nuxt",
        "react" | "react-dom" => "react",
        "@angular/core" => "angular",
        "svelte" => "svelte",
        "fastify" => "fastify",
        "koa" => "koa",
        "hono" => "hono",
        _ => return None,
    })
}

fn detect_needles(text: &str, needles: &[(&str, &str)]) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut out = Vec::new();
    for (needle, name) in needles {
        if lower.contains(needle) && !out.iter().any(|e: &String| e == name) {
            out.push((*name).to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;

    #[test]
    fn language_from_extension() {
        assert_eq!(language_for_path(Path::new("a.rs")), Some("Rust"));
        assert_eq!(language_for_path(Path::new("a.ts")), Some("TypeScript"));
        assert_eq!(language_for_path(Path::new("a.md")), None);
    }

    #[test]
    fn package_json_detects_express_and_react() {
        let json = r#"{"dependencies":{"express":"4.18.2","react":"18.2.0"}}"#;
        let fws = frameworks_from_package_json(json);
        assert!(fws.contains(&"express".to_string()));
        assert!(fws.contains(&"react".to_string()));
    }

    #[test]
    fn skips_node_modules_and_target() {
        let tmp = std::env::temp_dir().join(format!("rz-inv-{}", crate::types::uuid_v4()));
        fs::create_dir_all(tmp.join("node_modules/pkg")).unwrap();
        fs::create_dir_all(tmp.join("src")).unwrap();
        fs::write(tmp.join("node_modules/pkg/index.js"), "x").unwrap();
        fs::write(tmp.join("src/main.rs"), "fn main() {}").unwrap();
        let files = collect_repo_files(&tmp);
        assert!(files.iter().any(|p| p.ends_with("main.rs")));
        assert!(!files
            .iter()
            .any(|p| p.to_string_lossy().contains("node_modules")));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn analyze_counts_entrypoint() {
        let tmp = std::env::temp_dir().join(format!("rz-inv2-{}", crate::types::uuid_v4()));
        fs::create_dir_all(&tmp).unwrap();
        let mut f = fs::File::create(tmp.join("server.js")).unwrap();
        writeln!(f, "console.log(1)").unwrap();
        fs::write(
            tmp.join("package.json"),
            r#"{"dependencies":{"express":"1.0.0"}}"#,
        )
        .unwrap();
        let files = collect_repo_files(&tmp);
        let (inv, finding) = analyze(&tmp, &files);
        assert!(inv.languages.contains(&"JavaScript".to_string()));
        assert!(inv.frameworks.contains(&"express".to_string()));
        assert!(inv.entrypoints.iter().any(|e| e.ends_with("server.js")));
        assert_eq!(finding.plugin, "sast/inventory");
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn skip_dir_hides_vcs_and_generated_only() {
        // Version control internals and generated/cache trees are skipped.
        assert!(should_skip_dir(".git"));
        assert!(should_skip_dir("node_modules"));
        assert!(should_skip_dir("TARGET"));
        assert!(should_skip_dir(".venv"));
        assert!(should_skip_dir(".terraform"));
        // Security-relevant dot-config directories are NOT skipped.
        assert!(!should_skip_dir(".github"));
        assert!(!should_skip_dir(".circleci"));
        assert!(!should_skip_dir(".gitlab"));
        assert!(!should_skip_dir(".devcontainer"));
        assert!(!should_skip_dir("src"));
    }

    #[test]
    fn walk_includes_github_workflows() {
        let tmp = std::env::temp_dir().join(format!("rz-gh-{}", crate::types::uuid_v4()));
        fs::create_dir_all(tmp.join(".github/workflows")).unwrap();
        fs::create_dir_all(tmp.join(".git")).unwrap();
        fs::write(tmp.join(".github/workflows/ci.yml"), "on: push").unwrap();
        fs::write(tmp.join(".git/config"), "[core]").unwrap();
        let files = collect_repo_files(&tmp);
        assert!(
            files
                .iter()
                .any(|p| p.ends_with(".github/workflows/ci.yml")),
            "CI workflow files must be walked"
        );
        assert!(
            !files.iter().any(|p| p.to_string_lossy().contains("/.git/")),
            ".git internals must stay skipped"
        );
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn gitignore_skips_ignored_dir() {
        let tmp = std::env::temp_dir().join(format!("rz-ign-{}", crate::types::uuid_v4()));
        fs::create_dir_all(tmp.join("src")).unwrap();
        fs::create_dir_all(tmp.join("ignored_dir")).unwrap();
        fs::write(tmp.join(".gitignore"), "ignored_dir/\n").unwrap();
        fs::write(tmp.join("src/ok.js"), "console.log(1)").unwrap();
        fs::write(tmp.join("ignored_dir/secret.js"), "eval(1)").unwrap();
        let files = collect_repo_files(&tmp);
        assert!(files.iter().any(|p| p.ends_with("ok.js")));
        assert!(!files
            .iter()
            .any(|p| p.to_string_lossy().contains("ignored_dir")));
        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn rustzapignore_skips_extra_paths() {
        let tmp = std::env::temp_dir().join(format!("rz-rzi-{}", crate::types::uuid_v4()));
        fs::create_dir_all(tmp.join("src")).unwrap();
        fs::create_dir_all(tmp.join("scratch")).unwrap();
        fs::write(tmp.join(".rustzapignore"), "scratch/\n").unwrap();
        fs::write(tmp.join("src/ok.js"), "x").unwrap();
        fs::write(tmp.join("scratch/nope.js"), "eval(1)").unwrap();
        let files = collect_repo_files(&tmp);
        assert!(files.iter().any(|p| p.ends_with("ok.js")));
        assert!(!files
            .iter()
            .any(|p| p.to_string_lossy().contains("scratch")));
        let _ = fs::remove_dir_all(&tmp);
    }
}
