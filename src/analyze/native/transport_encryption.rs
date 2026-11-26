//! Deployment evidence for transport, backup and storage encryption (issue #47).
//!
//! Compose and Kubernetes YAML are parsed with `serde_yaml`. Effective env
//! values are resolved from `environment:`, `env_file:`, the project `.env`
//! (`${VAR}` / `${VAR:-default}` interpolation), container `env:` /
//! `$(VAR)` references and same-repo ConfigMaps. A value that cannot be
//! resolved statically is reported as "unknown effective value", never guessed.
//!
//! Plugins:
//! - `iac/transport-encryption`: PostgreSQL `sslmode`, `redis://`, `amqp://`,
//!   internal `http://` hops, SMTP without STARTTLS/TLS.
//! - `iac/backup-encryption`: `pg_dump`/`mysqldump`/upload `tar` pipelines with
//!   or without an identified encryption stage.
//! - `iac/storage-encryption`: Secret / StorageClass / VolumeSnapshotClass / PVC
//!   encryption, "verified" only with matching deployment evidence.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde_yaml::Value;

use crate::analyze::inventory::{
    extension_lower, file_url, line_number, read_text_head, rel_path, MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::types::{CodeLocation, Confidence, Finding, Severity};

pub const TRANSPORT_PLUGIN: &str = "iac/transport-encryption";
pub const BACKUP_PLUGIN: &str = "iac/backup-encryption";
pub const STORAGE_PLUGIN: &str = "iac/storage-encryption";

const MAX_FINDINGS: usize = 200;
const OWASP: &str = "A02:2021 – Cryptographic Failures";

/// Deployment artifact position (repo-relative file, 1-based line).
#[derive(Clone, Debug)]
struct Origin {
    file: String,
    line: u32,
}

/// Effective env value; `value == None` means it cannot be known statically.
#[derive(Clone, Debug)]
struct EnvVal {
    value: Option<String>,
    origin: Origin,
    /// How the value was resolved (interpolation, default) or why it is unknown.
    note: Option<String>,
}

/// One runtime unit: a compose service or a Kubernetes container.
struct Unit {
    service: String,
    env: BTreeMap<String, EnvVal>,
    commands: Vec<(String, Origin)>,
    peers: HashSet<String>,
}

/// One parsed Kubernetes YAML document.
struct K8sDoc {
    value: Value,
    file: String,
    start_line: u32,
    src: String,
}

fn re(cell: &'static OnceLock<Regex>, pat: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pat).expect("static transport_encryption regex"))
}

/// Mask credentials in URLs, `KEY=secret` pairs and `mysqldump -psecret`.
pub fn redact(s: &str) -> String {
    static URL: OnceLock<Regex> = OnceLock::new();
    static KV: OnceLock<Regex> = OnceLock::new();
    static MYSQL_P: OnceLock<Regex> = OnceLock::new();
    let s = re(&URL, r"(?i)([a-z][a-z0-9+.\-]*://)([^:/@\s]*):([^@\s/]+)@")
        .replace_all(s, "${1}${2}:***@");
    let s = re(
        &KV,
        r"(?i)\b([a-z0-9_]*(?:pass(?:word)?|pwd|secret|token)[a-z0-9_]*)=[^\s&]+",
    )
    .replace_all(&s, "${1}=***");
    re(&MYSQL_P, r"(\s)-p[^\s-]\S*")
        .replace_all(&s, "${1}-p***")
        .into_owned()
}

fn scalar(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        Value::Bool(b) => Some(b.to_string()),
        _ => None,
    }
}

fn str_or_seq(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Sequence(seq)) => seq.iter().filter_map(scalar).collect(),
        Some(v) => scalar(v).into_iter().collect(),
        None => Vec::new(),
    }
}

/// First line at or after `from` (1-based) that contains `needle`.
fn find_line(src: &str, from: u32, needle: &str) -> u32 {
    let skip = from.saturating_sub(1) as usize;
    src.lines()
        .enumerate()
        .skip(skip)
        .find(|(_, l)| l.contains(needle))
        .map(|(i, _)| i as u32 + 1)
        .unwrap_or(from.max(1))
}

/// Resolve `${VAR}`, `${VAR:-def}`, `${VAR-def}` and `$VAR` against `vars`.
/// `Err(var)` names the first variable with no supplied value or default.
fn interpolate(raw: &str, vars: &HashMap<String, String>) -> Result<(String, bool), String> {
    static VAR: OnceLock<Regex> = OnceLock::new();
    let re = re(
        &VAR,
        r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-?])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)",
    );
    let mut out = String::new();
    let mut last = 0;
    let mut used = false;
    for c in re.captures_iter(raw) {
        let m = c.get(0).expect("match");
        let name = c.get(1).or_else(|| c.get(4)).expect("var name").as_str();
        let op = c.get(2).map(|m| m.as_str()).unwrap_or("");
        let supplied = vars
            .get(name)
            .filter(|v| !(op.starts_with(':') && v.is_empty()));
        let val = match (supplied, op) {
            (Some(v), _) => v.clone(),
            (None, ":-" | "-") => c.get(3).map(|m| m.as_str()).unwrap_or("").to_string(),
            _ => return Err(name.to_string()),
        };
        out.push_str(&raw[last..m.start()]);
        out.push_str(&val);
        last = m.end();
        used = true;
    }
    out.push_str(&raw[last..]);
    Ok((out, used))
}

/// Parse a dotenv-style file inside `root`. Missing / outside-root files yield `None`.
fn read_env_file(root: &Path, path: &Path) -> Option<Vec<(String, String, Origin)>> {
    let canon_root = root.canonicalize().ok()?;
    let canon = path.canonicalize().ok()?;
    if !canon.starts_with(&canon_root) {
        return None;
    }
    let (src, _) = read_text_head(&canon, MAX_SOURCE_BYTES)?;
    let file = canon
        .strip_prefix(&canon_root)
        .map(|p| p.to_string_lossy().replace('\\', "/"))
        .unwrap_or_default();
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line);
        if let Some((k, v)) = line.split_once('=') {
            let v = v.trim().trim_matches(|c| c == '"' || c == '\'');
            out.push((
                k.trim().to_string(),
                v.to_string(),
                Origin {
                    file: file.clone(),
                    line: i as u32 + 1,
                },
            ));
        }
    }
    Some(out)
}

fn env_entry(raw: Option<String>, vars: &HashMap<String, String>, origin: Origin) -> EnvVal {
    let Some(raw) = raw else {
        return EnvVal {
            value: None,
            origin,
            note: Some("value passed through from the deploy-time shell".into()),
        };
    };
    match interpolate(&raw, vars) {
        Ok((v, used)) => EnvVal {
            value: Some(v),
            origin,
            note: used.then(|| format!("interpolated from `{raw}` via .env/defaults")),
        },
        Err(var) => EnvVal {
            value: None,
            origin,
            note: Some(format!("`${{{var}}}` has no supplied value or default")),
        },
    }
}

// ---------------------------------------------------------------------------
// Compose
// ---------------------------------------------------------------------------

fn is_compose(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    (name.starts_with("docker-compose") || name.starts_with("compose."))
        && matches!(extension_lower(path).as_deref(), Some("yml" | "yaml"))
}

fn compose_units(root: &Path, path: &Path, rel: &str, src: &str) -> Vec<Unit> {
    let Ok(doc) = serde_yaml::from_str::<Value>(src) else {
        return Vec::new();
    };
    let Some(services) = doc.get("services").and_then(Value::as_mapping) else {
        return Vec::new();
    };
    let dir = path.parent().unwrap_or(root);
    // Compose interpolation source: the project `.env`.
    let vars: HashMap<String, String> = read_env_file(root, &dir.join(".env"))
        .unwrap_or_default()
        .into_iter()
        .map(|(k, v, _)| (k, v))
        .collect();
    let peers: HashSet<String> = services.keys().filter_map(scalar).collect();

    let mut units = Vec::new();
    for (name, svc) in services {
        let Some(name) = scalar(name) else { continue };
        let header = format!("{name}:");
        let svc_line = src
            .lines()
            .position(|l| l.trim_start().starts_with(&header))
            .map_or(1, |i| i as u32 + 1);
        let at = |needle: &str| Origin {
            file: rel.to_string(),
            line: find_line(src, svc_line, needle),
        };
        let mut env = BTreeMap::new();

        // env_file first: `environment:` takes precedence over it.
        let env_files: Vec<String> = match svc.get("env_file") {
            Some(Value::Sequence(seq)) => seq
                .iter()
                .filter_map(|e| scalar(e).or_else(|| e.get("path").and_then(scalar)))
                .collect(),
            other => str_or_seq(other),
        };
        for f in env_files {
            match read_env_file(root, &dir.join(&f)) {
                Some(entries) => {
                    for (k, v, origin) in entries {
                        env.insert(k, env_entry(Some(v), &vars, origin));
                    }
                }
                None => {
                    // Unknown file contents: record the gap instead of guessing.
                    env.insert(
                        format!("<env_file:{f}>"),
                        EnvVal {
                            value: None,
                            origin: at(&f),
                            note: Some(format!("env_file `{f}` was not supplied")),
                        },
                    );
                }
            }
        }

        match svc.get("environment") {
            Some(Value::Mapping(m)) => {
                for (k, v) in m {
                    let Some(k) = scalar(k) else { continue };
                    let origin = at(&k);
                    env.insert(k, env_entry(scalar(v), &vars, origin));
                }
            }
            Some(Value::Sequence(seq)) => {
                for item in seq.iter().filter_map(scalar) {
                    let (k, v) = match item.split_once('=') {
                        Some((k, v)) => (k.to_string(), Some(v.to_string())),
                        None => (item.clone(), None),
                    };
                    let origin = at(&k);
                    env.insert(k, env_entry(v, &vars, origin));
                }
            }
            _ => {}
        }

        let mut commands = Vec::new();
        for key in ["entrypoint", "command"] {
            let cmd = str_or_seq(svc.get(key)).join(" ");
            if !cmd.is_empty() {
                commands.push((cmd, at(&format!("{key}:"))));
            }
        }

        units.push(Unit {
            service: format!("compose service `{name}`"),
            env,
            commands,
            peers: peers.clone(),
        });
    }
    units
}

// ---------------------------------------------------------------------------
// Kubernetes
// ---------------------------------------------------------------------------

fn split_docs(src: &str) -> Vec<(u32, String)> {
    let mut docs = Vec::new();
    let mut cur = String::new();
    let mut start = 1u32;
    for (i, line) in src.lines().enumerate() {
        if line.starts_with("---") {
            docs.push((start, std::mem::take(&mut cur)));
            start = i as u32 + 2;
        } else {
            cur.push_str(line);
            cur.push('\n');
        }
    }
    docs.push((start, cur));
    docs
}

fn k8s_docs(rel: &str, src: &str) -> Vec<K8sDoc> {
    split_docs(src)
        .into_iter()
        .filter_map(|(start_line, chunk)| {
            let value: Value = serde_yaml::from_str(&chunk).ok()?;
            value.get("kind")?;
            Some(K8sDoc {
                value,
                file: rel.to_string(),
                start_line,
                src: chunk,
            })
        })
        .collect()
}

impl K8sDoc {
    fn kind(&self) -> &str {
        self.value.get("kind").and_then(Value::as_str).unwrap_or("")
    }
    fn name(&self) -> String {
        self.value
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(scalar)
            .unwrap_or_default()
    }
    fn origin(&self, needle: &str) -> Origin {
        Origin {
            file: self.file.clone(),
            line: self.start_line + find_line(&self.src, 1, needle) - 1,
        }
    }
}

fn collect_containers<'a>(v: &'a Value, out: &mut Vec<&'a Value>) {
    match v {
        Value::Mapping(m) => {
            for (k, child) in m {
                let key = k.as_str().unwrap_or("");
                if matches!(key, "containers" | "initContainers") {
                    if let Some(seq) = child.as_sequence() {
                        out.extend(seq.iter());
                        continue;
                    }
                }
                collect_containers(child, out);
            }
        }
        Value::Sequence(seq) => seq.iter().for_each(|c| collect_containers(c, out)),
        _ => {}
    }
}

type ConfigMaps = HashMap<String, Vec<(String, String, Origin)>>;

fn k8s_units(docs: &[K8sDoc], config_maps: &ConfigMaps) -> Vec<Unit> {
    const WORKLOADS: &[&str] = &[
        "Pod",
        "Deployment",
        "StatefulSet",
        "DaemonSet",
        "ReplicaSet",
        "Job",
        "CronJob",
    ];
    let mut units = Vec::new();
    for doc in docs.iter().filter(|d| WORKLOADS.contains(&d.kind())) {
        let mut containers = Vec::new();
        collect_containers(&doc.value, &mut containers);
        for c in containers {
            let cname = c.get("name").and_then(scalar).unwrap_or_default();
            let mut env: BTreeMap<String, EnvVal> = BTreeMap::new();
            for from in c
                .get("envFrom")
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
            {
                if let Some(cm) = from
                    .get("configMapRef")
                    .and_then(|r| r.get("name"))
                    .and_then(scalar)
                {
                    match config_maps.get(&cm) {
                        Some(entries) => {
                            for (k, v, origin) in entries {
                                env.insert(
                                    k.clone(),
                                    EnvVal {
                                        value: Some(v.clone()),
                                        origin: origin.clone(),
                                        note: Some(format!("from ConfigMap `{cm}`")),
                                    },
                                );
                            }
                        }
                        None => {
                            env.insert(
                                format!("<configMap:{cm}>"),
                                EnvVal {
                                    value: None,
                                    origin: doc.origin(&cm),
                                    note: Some(format!("ConfigMap `{cm}` was not supplied")),
                                },
                            );
                        }
                    }
                }
            }
            for e in c
                .get("env")
                .and_then(Value::as_sequence)
                .into_iter()
                .flatten()
            {
                let Some(name) = e.get("name").and_then(scalar) else {
                    continue;
                };
                let origin = doc.origin(&format!("name: {name}"));
                let val = if let Some(raw) = e.get("value").and_then(scalar) {
                    // Kubernetes `$(VAR)` dependent-variable expansion.
                    let vars: HashMap<String, String> = env
                        .iter()
                        .filter_map(|(k, v)| v.value.clone().map(|v| (k.clone(), v)))
                        .collect();
                    static K8S_VAR: OnceLock<Regex> = OnceLock::new();
                    let k8s_var = re(&K8S_VAR, r"\$\(([A-Za-z_][A-Za-z0-9_]*)\)");
                    if k8s_var.is_match(&raw) {
                        let as_compose = k8s_var.replace_all(&raw, "$${$1}").into_owned();
                        env_entry(Some(as_compose), &vars, origin)
                    } else {
                        EnvVal {
                            value: Some(raw),
                            origin,
                            note: None,
                        }
                    }
                } else if let Some(r) = e.get("valueFrom").and_then(|v| v.get("configMapKeyRef")) {
                    let cm = r.get("name").and_then(scalar).unwrap_or_default();
                    let key = r.get("key").and_then(scalar).unwrap_or_default();
                    match config_maps
                        .get(&cm)
                        .and_then(|es| es.iter().find(|(k, _, _)| *k == key))
                    {
                        Some((_, v, o)) => EnvVal {
                            value: Some(v.clone()),
                            origin: o.clone(),
                            note: Some(format!("from ConfigMap `{cm}` key `{key}`")),
                        },
                        None => EnvVal {
                            value: None,
                            origin,
                            note: Some(format!("ConfigMap `{cm}` key `{key}` was not supplied")),
                        },
                    }
                } else {
                    EnvVal {
                        value: None,
                        origin,
                        note: Some("value comes from a Secret/field reference".into()),
                    }
                };
                env.insert(name, val);
            }
            let mut commands = Vec::new();
            let cmd = [str_or_seq(c.get("command")), str_or_seq(c.get("args"))]
                .concat()
                .join(" ");
            if !cmd.is_empty() {
                commands.push((cmd, doc.origin("command:")));
            }
            units.push(Unit {
                service: format!("{} `{}` container `{cname}`", doc.kind(), doc.name()),
                env,
                commands,
                peers: HashSet::new(),
            });
        }
    }
    units
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn finding(
    root: &Path,
    plugin: &str,
    param: &str,
    title: &str,
    severity: Severity,
    service: &str,
    origin: &Origin,
    detail: String,
    remediation: &str,
    evidence: String,
    confidence: Confidence,
) -> Finding {
    Finding::new(
        title,
        severity,
        file_url(&root.join(&origin.file), Some(origin.line)),
        format!(
            "{detail} Service: {service}. Artifact: {}:{}.",
            origin.file, origin.line
        ),
        remediation,
        plugin,
    )
    .with_source_tool(SOURCE_TOOL)
    .with_parameter(param)
    .with_evidence(redact(&evidence))
    .with_cwe(319)
    .with_owasp(OWASP)
    .with_location(CodeLocation {
        file: origin.file.clone(),
        line_start: origin.line,
        line_end: None,
    })
    .with_confidence(confidence)
}

fn is_truthy(v: &str) -> bool {
    matches!(
        v.trim().to_ascii_lowercase().as_str(),
        "true" | "1" | "yes" | "on" | "required" | "starttls" | "tls" | "ssl"
    )
}

fn is_internal_host(host: &str, peers: &HashSet<String>) -> bool {
    let h = host.to_ascii_lowercase();
    if h == "localhost" || h.starts_with("127.") || h == "0.0.0.0" || h.is_empty() {
        return false;
    }
    peers.contains(&h)
        || !h.contains('.')
        || [".svc", ".svc.cluster.local", ".cluster.local", ".internal"]
            .iter()
            .any(|s| h.ends_with(s))
}

fn check_unit(root: &Path, u: &Unit, out: &mut Vec<Finding>) {
    static TRANSPORT_KEY: OnceLock<Regex> = OnceLock::new();
    static URL: OnceLock<Regex> = OnceLock::new();
    static SSLMODE_Q: OnceLock<Regex> = OnceLock::new();
    static SMTP_HOST: OnceLock<Regex> = OnceLock::new();
    static SMTP_TLS: OnceLock<Regex> = OnceLock::new();
    static SMTP_PORT: OnceLock<Regex> = OnceLock::new();
    let transport_key = re(
        &TRANSPORT_KEY,
        r"(?i)url|uri|dsn|sslmode|ssl_mode|tls|ssl|smtp|amqp|redis|postgres|database|broker|^<",
    );
    let url_re = re(
        &URL,
        r"(?i)\b(postgres(?:ql)?|rediss?|amqps?|https?|smtps?)://[^\s'\x22,;]+",
    );
    let sslmode_q = re(&SSLMODE_Q, r"(?i)[?&]sslmode=([a-z-]+)");
    let smtp_host = re(&SMTP_HOST, r"(?i)^(smtp|mail|email)_?(host|server|url)$");
    let smtp_tls = re(&SMTP_TLS, r"(?i)(smtp|mail|email).*(tls|ssl|secure)");
    let smtp_port = re(&SMTP_PORT, r"(?i)(smtp|mail|email).*port");

    let env_sslmode = u
        .env
        .iter()
        .find(|(k, _)| k.to_ascii_lowercase().contains("sslmode"));
    let smtp_tls_vals: Vec<&EnvVal> = u
        .env
        .iter()
        .filter(|(k, _)| smtp_tls.is_match(k))
        .map(|(_, v)| v)
        .collect();
    let smtp_tls_on = smtp_tls_vals
        .iter()
        .any(|v| v.value.as_deref().is_some_and(is_truthy));

    for (key, ev) in &u.env {
        let conf = if ev.note.is_some() {
            Confidence::Tentative
        } else {
            Confidence::Firm
        };
        let Some(value) = &ev.value else {
            if transport_key.is_match(key) {
                out.push(finding(
                    root,
                    TRANSPORT_PLUGIN,
                    "unknown-effective-value",
                    "Transport setting has unknown effective value",
                    Severity::Info,
                    &u.service,
                    &ev.origin,
                    format!(
                        "`{key}`: unknown effective value ({}); its TLS posture cannot be verified from the supplied deployment inputs.",
                        ev.note.as_deref().unwrap_or("not resolvable")
                    ),
                    "Supply the rendered environment (.env, env_file, ConfigMap) or verify TLS settings at deploy time.",
                    format!("{key}=<unknown effective value>"),
                    Confidence::Tentative,
                ));
            }
            continue;
        };
        let evidence = format!(
            "{key}={value}{}",
            ev.note
                .as_ref()
                .map(|n| format!(" ({n})"))
                .unwrap_or_default()
        );

        if key.to_ascii_lowercase().contains("sslmode") {
            let mode = value.trim().to_ascii_lowercase();
            if matches!(mode.as_str(), "disable" | "allow" | "prefer" | "require") {
                out.push(pg_finding(root, u, ev, &mode, evidence.clone(), conf));
            }
        }

        for m in url_re.captures_iter(value) {
            let url = m.get(0).expect("match").as_str();
            match m[1].to_ascii_lowercase().as_str() {
                "postgres" | "postgresql" => {
                    if let Some(mode) = sslmode_q.captures(url) {
                        let mode = mode[1].to_ascii_lowercase();
                        if !mode.starts_with("verify") {
                            out.push(pg_finding(root, u, ev, &mode, evidence.clone(), conf));
                        }
                    } else if env_sslmode.is_none() {
                        out.push(pg_finding(
                            root,
                            u,
                            ev,
                            "prefer (libpq default; no sslmode set)",
                            evidence.clone(),
                            Confidence::Tentative,
                        ));
                    }
                }
                s @ ("redis" | "amqp") => {
                    let (title, fix) = if s == "redis" {
                        (
                            "Redis connection without TLS (redis://)",
                            "Use `rediss://` with certificate verification.",
                        )
                    } else {
                        (
                            "AMQP connection without TLS (amqp://)",
                            "Use `amqps://` with certificate verification.",
                        )
                    };
                    out.push(finding(
                        root,
                        TRANSPORT_PLUGIN,
                        &format!("{s}-plaintext"),
                        title,
                        Severity::Medium,
                        &u.service,
                        &ev.origin,
                        format!("`{key}` connects to {s} in cleartext."),
                        fix,
                        evidence.clone(),
                        conf,
                    ));
                }
                "http" => {
                    let rest = url.split_once("://").map(|(_, r)| r).unwrap_or("");
                    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
                    let host = authority
                        .rsplit_once('@')
                        .map(|(_, h)| h)
                        .unwrap_or(authority)
                        .split(':')
                        .next()
                        .unwrap_or("");
                    if is_internal_host(host, &u.peers) {
                        out.push(finding(
                            root,
                            TRANSPORT_PLUGIN,
                            "internal-http-hop",
                            "Internal service hop over plain HTTP",
                            Severity::Low,
                            &u.service,
                            &ev.origin,
                            format!(
                                "`{key}` calls internal host `{host}` over unencrypted http://."
                            ),
                            "Use HTTPS/mTLS (e.g. a service mesh) for service-to-service traffic.",
                            evidence.clone(),
                            conf,
                        ));
                    }
                }
                "smtp" if !smtp_tls_on => {
                    out.push(smtp_finding(root, u, ev, evidence.clone(), conf));
                }
                _ => {}
            }
        }
    }

    // SMTP configured by host/port keys rather than a URL.
    let host_entry = u.env.iter().find(|(k, _)| smtp_host.is_match(k));
    if let Some((_, host_ev)) = host_entry {
        let has_url = host_ev.value.as_deref().is_some_and(|v| v.contains("://"));
        let implicit_tls = u.env.iter().any(|(k, v)| {
            smtp_port.is_match(k) && v.value.as_deref().map(str::trim) == Some("465")
        });
        let explicit_off = smtp_tls_vals
            .iter()
            .find(|v| v.value.as_deref().is_some_and(|x| !is_truthy(x)));
        if !has_url && !smtp_tls_on && !implicit_tls {
            if let Some(off) = explicit_off {
                let ev = (*off).clone();
                let evidence = format!(
                    "SMTP TLS setting = {}",
                    ev.value.clone().unwrap_or_default()
                );
                out.push(smtp_finding(root, u, &ev, evidence, Confidence::Firm));
            } else if smtp_tls_vals.is_empty() {
                let evidence = format!(
                    "SMTP host = {}; no STARTTLS/TLS setting",
                    host_ev
                        .value
                        .as_deref()
                        .unwrap_or("<unknown effective value>")
                );
                out.push(smtp_finding(
                    root,
                    u,
                    host_ev,
                    evidence,
                    Confidence::Tentative,
                ));
            }
            // Otherwise a TLS key exists with an unknown value: already reported above.
        }
    }
}

fn pg_finding(
    root: &Path,
    u: &Unit,
    ev: &EnvVal,
    mode: &str,
    evidence: String,
    conf: Confidence,
) -> Finding {
    let sev = if mode == "disable" {
        Severity::High
    } else {
        Severity::Medium
    };
    finding(
        root,
        TRANSPORT_PLUGIN,
        "postgres-sslmode",
        "PostgreSQL connection without TLS certificate verification",
        sev,
        &u.service,
        &ev.origin,
        format!("Effective sslmode is `{mode}`; only `verify-ca`/`verify-full` authenticate the server."),
        "Set `sslmode=verify-full` and provide the server CA (`sslrootcert`).",
        evidence,
        conf,
    )
}

fn smtp_finding(root: &Path, u: &Unit, ev: &EnvVal, evidence: String, conf: Confidence) -> Finding {
    finding(
        root,
        TRANSPORT_PLUGIN,
        "smtp-no-tls",
        "SMTP without STARTTLS/TLS",
        Severity::Medium,
        &u.service,
        &ev.origin,
        "No enabled STARTTLS/implicit-TLS setting was identified for the SMTP relay.".into(),
        "Enable STARTTLS (required) or implicit TLS (port 465 / smtps://) with certificate verification.",
        evidence,
        conf,
    )
}

/// Backup pipeline: a dump/archive step with or without an encryption stage.
fn check_backup(root: &Path, service: &str, text: &str, origin: &Origin, out: &mut Vec<Finding>) {
    static DUMP: OnceLock<Regex> = OnceLock::new();
    static ENC: OnceLock<Regex> = OnceLock::new();
    static NO_ENC: OnceLock<Regex> = OnceLock::new();
    let dump = re(
        &DUMP,
        r"(?i)\b(?:pg_dump(?:all)?|mysqldump|mariadb-dump|mongodump)\b[^\n]*|\btar\b[^\n]*\b(?:uploads?|media|storage|attachments)\b[^\n]*",
    );
    let enc = re(
        &ENC,
        r"(?i)\bgpg2?\b|\bage\s+(?:-r|--recipient|-e|--encrypt|-p|--passphrase|-R)\b|\bopenssl\s+(?:enc|smime|cms)\b|\brestic\b|\bborg\s+(?:create|init)\b|--sse\b|--sse-kms|--sse-c\b|--encrypt(?:ion)?-key|--kms-key",
    );
    let no_enc = re(&NO_ENC, r"(?i)--encryption[= ]none\b");
    let Some(m) = dump.find(text) else { return };
    let origin = Origin {
        file: origin.file.clone(),
        line: origin.line + line_number(text, m.start()) - 1,
    };
    let evidence = m.as_str().trim().to_string();
    if enc.is_match(text) && !no_enc.is_match(text) {
        out.push(
            finding(
                root,
                BACKUP_PLUGIN,
                "backup-encryption-verified",
                "Backup encryption stage identified (verified)",
                Severity::Info,
                service,
                &origin,
                "Backup pipeline pipes its dump/archive through an identified encryption stage."
                    .into(),
                "Keep encryption keys outside the backup target and test restores regularly.",
                evidence,
                Confidence::Firm,
            )
            .with_cwe(311),
        );
    } else {
        out.push(
            finding(
                root,
                BACKUP_PLUGIN,
                "backup-unencrypted",
                "Backup pipeline without identified encryption stage",
                Severity::Medium,
                service,
                &origin,
                "A database dump or upload archive is written with no identified encryption stage (gpg, age, openssl enc, restic, borg, --sse).".into(),
                "Encrypt backups before they leave the host (gpg/age/restic) or use server-side KMS encryption.",
                evidence,
                Confidence::Tentative,
            )
            .with_cwe(311),
        );
    }
}

const KMS_PARAMS: &[&str] = &[
    "kmsKeyId",
    "kms-key-id",
    "kmsKeyName",
    "disk-encryption-kms-key",
    "diskEncryptionSetID",
    "diskEncryptionSetId",
    "encryptionKey",
];

/// `Some(true)` = encrypted evidence, `Some(false)` = explicitly off, `None` = no evidence.
fn param_encryption(params: Option<&Value>) -> Option<bool> {
    let params = params?;
    if let Some(v) = params.get("encrypted").and_then(scalar) {
        return Some(v.trim().eq_ignore_ascii_case("true"));
    }
    KMS_PARAMS
        .iter()
        .any(|k| {
            params
                .get(*k)
                .and_then(scalar)
                .is_some_and(|v| !v.is_empty())
        })
        .then_some(true)
}

fn check_storage(root: &Path, docs: &[K8sDoc], out: &mut Vec<Finding>) {
    let info = |out: &mut Vec<Finding>,
                param: &str,
                title: &str,
                sev: Severity,
                what: &str,
                origin: &Origin,
                detail: String,
                evidence: String,
                conf: Confidence| {
        out.push(
            finding(
                root,
                STORAGE_PLUGIN,
                param,
                title,
                sev,
                what,
                origin,
                detail,
                "Supply deployment evidence: EncryptionConfiguration for Secrets, StorageClass/VolumeSnapshotClass `encrypted: \"true\"` or a KMS key parameter.",
                evidence,
                conf,
            )
            .with_cwe(311),
        );
    };

    // Kubernetes Secrets at rest.
    let mut secrets_verified = false;
    for d in docs
        .iter()
        .filter(|d| d.kind() == "EncryptionConfiguration")
    {
        for r in d
            .value
            .get("resources")
            .and_then(Value::as_sequence)
            .into_iter()
            .flatten()
        {
            let covers = str_or_seq(r.get("resources"))
                .iter()
                .any(|x| x == "secrets" || x == "*.*");
            if !covers {
                continue;
            }
            let first = r
                .get("providers")
                .and_then(Value::as_sequence)
                .and_then(|p| p.first())
                .and_then(Value::as_mapping)
                .and_then(|m| m.keys().next())
                .and_then(scalar)
                .unwrap_or_default();
            let origin = d.origin("providers:");
            if first == "identity" || first.is_empty() {
                info(out, "secrets-unencrypted", "Kubernetes Secrets written unencrypted (identity provider first)", Severity::Medium,
                    "EncryptionConfiguration", &origin,
                    "The first provider for `secrets` is `identity`, so new Secrets are stored in etcd in plaintext.".into(),
                    format!("first provider: {}", if first.is_empty() { "<none>" } else { first.as_str() }), Confidence::Firm);
            } else {
                secrets_verified = true;
                info(
                    out,
                    "secrets-encryption-verified",
                    "Kubernetes Secret encryption at rest verified",
                    Severity::Info,
                    "EncryptionConfiguration",
                    &origin,
                    format!("EncryptionConfiguration encrypts `secrets` with `{first}`."),
                    format!("first provider: {first}"),
                    Confidence::Firm,
                );
            }
        }
    }
    if !secrets_verified {
        if let Some(s) = docs.iter().find(|d| d.kind() == "Secret") {
            info(out, "secrets-encryption-not-verified", "Kubernetes Secret encryption at rest not verified", Severity::Info,
                &format!("Secret `{}`", s.name()), &s.origin("kind:"),
                "Secrets are deployed but no EncryptionConfiguration covering `secrets` was supplied; encryption at rest is not verified.".into(),
                "kind: Secret".into(), Confidence::Tentative);
        }
    }

    // Disks and snapshots.
    let mut verified_classes = HashSet::new();
    for d in docs
        .iter()
        .filter(|d| matches!(d.kind(), "StorageClass" | "VolumeSnapshotClass"))
    {
        let name = d.name();
        let what = format!("{} `{name}`", d.kind());
        let target = if d.kind() == "StorageClass" {
            "disk"
        } else {
            "snapshot"
        };
        match param_encryption(d.value.get("parameters")) {
            Some(true) => {
                verified_classes.insert(name.clone());
                info(
                    out,
                    &format!("{target}-encryption-verified"),
                    &format!("{} encryption verified", capitalize(target)),
                    Severity::Info,
                    &what,
                    &d.origin("parameters:"),
                    format!("{what} sets an encryption parameter / KMS key."),
                    "parameters: encrypted / KMS key".into(),
                    Confidence::Firm,
                );
            }
            Some(false) => info(
                out,
                &format!("{target}-unencrypted"),
                &format!("{} encryption explicitly disabled", capitalize(target)),
                Severity::Medium,
                &what,
                &d.origin("encrypted:"),
                format!("{what} sets `encrypted: \"false\"`."),
                "parameters.encrypted: false".into(),
                Confidence::Firm,
            ),
            None => {
                let name_hint = if name.to_ascii_lowercase().contains("encrypt") {
                    " The class name suggests encryption, but a name alone is not evidence."
                } else {
                    ""
                };
                info(
                    out,
                    &format!("{target}-encryption-not-verified"),
                    &format!("{} encryption not verified", capitalize(target)),
                    Severity::Info,
                    &what,
                    &d.origin("kind:"),
                    format!("{what} has no `encrypted: \"true\"` or KMS key parameter.{name_hint}"),
                    format!("{what}: no encryption parameters"),
                    Confidence::Tentative,
                );
            }
        }
    }
    for d in docs.iter().filter(|d| d.kind() == "PersistentVolumeClaim") {
        let class = d
            .value
            .get("spec")
            .and_then(|s| s.get("storageClassName"))
            .and_then(scalar)
            .unwrap_or_default();
        if verified_classes.contains(&class) {
            continue;
        }
        let what = format!("PersistentVolumeClaim `{}`", d.name());
        info(
            out,
            "disk-encryption-not-verified",
            "Disk encryption not verified",
            Severity::Info,
            &what,
            &d.origin("kind:"),
            format!(
                "{what} uses StorageClass `{}` with no supplied encryption evidence.",
                if class.is_empty() {
                    "<cluster default>"
                } else {
                    class.as_str()
                }
            ),
            format!("storageClassName: {class}"),
            Confidence::Tentative,
        );
    }
}

fn capitalize(s: &str) -> String {
    let mut c = s.chars();
    c.next()
        .map(|f| f.to_uppercase().collect::<String>() + c.as_str())
        .unwrap_or_default()
}

pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut units = Vec::new();
    let mut docs = Vec::new();
    for path in files {
        let ext = extension_lower(path);
        let is_yaml = matches!(ext.as_deref(), Some("yml" | "yaml"));
        let is_shell = matches!(ext.as_deref(), Some("sh" | "bash"));
        if !is_yaml && !is_shell {
            continue;
        }
        let Some((src, _)) = read_text_head(path, MAX_SOURCE_BYTES) else {
            continue;
        };
        let rel = rel_path(root, path);
        if is_shell {
            let origin = Origin {
                file: rel.clone(),
                line: 1,
            };
            check_backup(root, &format!("script `{rel}`"), &src, &origin, &mut out);
        } else if is_compose(path) {
            units.extend(compose_units(root, path, &rel, &src));
        } else if src.contains("apiVersion:") && src.contains("kind:") {
            docs.extend(k8s_docs(&rel, &src));
        }
    }

    let mut config_maps: ConfigMaps = HashMap::new();
    for d in docs.iter().filter(|d| d.kind() == "ConfigMap") {
        let entries = d
            .value
            .get("data")
            .and_then(Value::as_mapping)
            .into_iter()
            .flatten()
            .filter_map(|(k, v)| {
                let k = scalar(k)?;
                let origin = d.origin(&format!("{k}:"));
                Some((k, scalar(v)?, origin))
            })
            .collect();
        config_maps.insert(d.name(), entries);
    }
    units.extend(k8s_units(&docs, &config_maps));

    for u in &units {
        check_unit(root, u, &mut out);
        for (cmd, origin) in &u.commands {
            check_backup(root, &u.service, cmd, origin, &mut out);
        }
    }
    check_storage(root, &docs, &mut out);
    out.truncate(MAX_FINDINGS);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_masks_url_and_kv_credentials() {
        assert_eq!(
            redact("postgres://app:s3cret@db:5432/app"),
            "postgres://app:***@db:5432/app"
        );
        assert_eq!(
            redact("PGPASSWORD=hunter2 pg_dump"),
            "PGPASSWORD=*** pg_dump"
        );
        assert_eq!(
            redact("mysqldump -uroot -phunter2 db"),
            "mysqldump -uroot -p*** db"
        );
    }

    #[test]
    fn interpolate_resolves_env_and_defaults() {
        let vars = HashMap::from([("MODE".to_string(), "disable".to_string())]);
        assert_eq!(
            interpolate("x?sslmode=${MODE}", &vars).unwrap(),
            ("x?sslmode=disable".into(), true)
        );
        assert_eq!(interpolate("${NOPE:-prefer}", &vars).unwrap().0, "prefer");
        assert_eq!(interpolate("${NOPE}", &vars), Err("NOPE".into()));
        assert_eq!(
            interpolate("plain", &vars).unwrap(),
            ("plain".into(), false)
        );
    }

    #[test]
    fn storage_class_name_alone_is_not_evidence() {
        assert_eq!(param_encryption(None), None);
        let p: Value = serde_yaml::from_str("type: gp3").unwrap();
        assert_eq!(param_encryption(Some(&p)), None);
        let p: Value = serde_yaml::from_str("encrypted: \"true\"").unwrap();
        assert_eq!(param_encryption(Some(&p)), Some(true));
        let p: Value = serde_yaml::from_str("kmsKeyId: arn:aws:kms:x").unwrap();
        assert_eq!(param_encryption(Some(&p)), Some(true));
    }

    #[test]
    fn internal_host_detection() {
        let peers = HashSet::from(["api".to_string()]);
        assert!(is_internal_host("api", &peers));
        assert!(is_internal_host("billing.prod.svc.cluster.local", &peers));
        assert!(!is_internal_host("localhost", &peers));
        assert!(!is_internal_host("example.com", &peers));
    }
}
