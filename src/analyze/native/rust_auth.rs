//! Syntax-aware authentication / authorization checks for Rust (Actix, Axum).
//!
//! Every non-test `.rs` file is parsed with `syn`; functions are indexed by
//! name to form a crate-local call graph, and supported route registrations
//! are resolved before anything about missing auth is reported:
//!
//! - Axum: `Router::new().route(..)`, `get(h).post(h2)`, `.layer(..)` /
//!   `.route_layer(..)` (apply to routes added before them), `.nest(..)`,
//!   `.merge(..)`, routers returned by helper functions and `let` bindings.
//! - Actix: `App::new()` / `web::scope(..)` / `web::resource(..)` with
//!   `.wrap(..)` (applies to the whole scope), `.service(..)`, `.route(..)`,
//!   `.to(..)`, `.configure(..)`, and `#[get("..")]`-style macros.
//! - A route counts as checked when a guarding layer/wrap, an auth extractor
//!   argument (`AuthUser`, `Claims`, custom `FromRequest(Parts)` types), or an
//!   auth call reachable through crate helpers is found.
//!
//! All findings share plugin `sast/rust-auth`; `parameter` is the rule id.
//! Write routes guarded only by a read permission are checked only when the
//! repo root holds [`PERMISSION_MAP_FILE`].

use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::path::{Path, PathBuf};

use quote::ToTokens;
use regex::Regex;
use serde::Deserialize;
use syn::punctuated::Punctuated;
use syn::spanned::Spanned;
use syn::visit::{self, Visit};
use syn::{Attribute, Expr, FnArg, Lit, Pat, Stmt, Type};

use crate::analyze::inventory::{
    extension_lower, file_url, read_text_capped, read_text_head, rel_path, MAX_SOURCE_BYTES,
};
use crate::analyze::native::SOURCE_TOOL;
use crate::types::{CodeLocation, Finding, Severity};

pub const PLUGIN: &str = "sast/rust-auth";
/// Optional `{"read": [...], "write": [...]}` permission mapping at the repo root.
pub const PERMISSION_MAP_FILE: &str = ".rustzap-permissions.json";

const LIMITS: &str = "Analysis limits: macro bodies are opaque, calls resolve by function name inside this crate only (no cross-crate, trait-object or dynamic dispatch), and dynamically built routers are not followed.";
const MAX_DEPTH: usize = 4;
const MAX_RESOLVE_DEPTH: usize = 8;
const MAX_FINDINGS: usize = 100;
// Fallback span maps are thread-local and offset-indexed by u32; keep well under.
const MAX_TOTAL_BYTES: usize = 256 * 1024 * 1024;
const METHODS: &[&str] = &[
    "get", "post", "put", "patch", "delete", "head", "options", "any",
];
const INPUT_WRAPPERS: &[&str] = &[
    "Json",
    "Form",
    "Query",
    "Path",
    "Multipart",
    "Bytes",
    "String",
    "Payload",
    "Option",
    "HttpRequest",
    "Request",
    "HeaderMap",
];

#[derive(Debug, Default, Deserialize)]
pub struct PermissionMap {
    #[serde(default)]
    pub read: BTreeSet<String>,
    #[serde(default)]
    pub write: BTreeSet<String>,
}

pub fn load_permission_map(root: &Path) -> Option<PermissionMap> {
    let text = read_text_capped(&root.join(PERMISSION_MAP_FILE), 1024 * 1024)?;
    serde_json::from_str(&text).ok()
}

pub fn scan(root: &Path, files: &[PathBuf]) -> Vec<Finding> {
    scan_with_permissions(root, files, load_permission_map(root).as_ref())
}

pub fn scan_with_permissions(
    root: &Path,
    files: &[PathBuf],
    perms: Option<&PermissionMap>,
) -> Vec<Finding> {
    let mut limits = Vec::new();
    let mut parsed = Vec::new();
    let mut total = 0usize;
    for path in files {
        if extension_lower(path).as_deref() != Some("rs") {
            continue;
        }
        let rel = rel_path(root, path);
        if rel.split('/').any(|c| c == "tests") {
            continue;
        }
        let Some((src, truncated)) = read_text_head(path, MAX_SOURCE_BYTES) else {
            continue;
        };
        if truncated || total + src.len() > MAX_TOTAL_BYTES {
            limits.push(format!("{rel}: skipped (size budget)"));
            continue;
        }
        total += src.len();
        match syn::parse_file(&src) {
            Ok(ast) => parsed.push(Parsed {
                rel,
                path: path.clone(),
                ast,
            }),
            Err(e) => limits.push(format!("{rel}: not parsed ({e})")),
        }
    }
    let out = if parsed.is_empty() && limits.is_empty() {
        Vec::new()
    } else {
        Analysis::new(&parsed, Rules::new()).run(perms, limits)
    };
    // All spans are consumed; release the thread-local source map.
    proc_macro2::extra::invalidate_current_thread_spans();
    out
}

struct Parsed {
    rel: String,
    path: PathBuf,
    ast: syn::File,
}

struct Rules {
    auth_call: Regex,
    auth_type: Regex,
    auth_layer: Regex,
    auth_ident: Regex,
    revoke: Regex,
    cred_update: Regex,
    cred_excluded: Regex,
    pw_ctx: Regex,
    default_cred: Regex,
    not_a_credential: Regex,
    public_route: Regex,
    admin_route: Regex,
}

impl Rules {
    fn new() -> Self {
        let re = |p: &str| Regex::new(p).expect("static rust_auth regex");
        Self {
            auth_call: re(
                r"(?i)^(?:(?:require|ensure|check|verify|assert|authorize|authenticate|enforce)_?\w*(?:auth|user|admin|perm|role|session|token|login|jwt|access|scope|claims)\w*|is_admin|is_authenticated|has_permission|has_role|has_scope|has_perm|authorize|authenticate|decode_jwt|verify_jwt|current_user|login_required)$",
            ),
            auth_type: re(
                r"(?i)^(?:\w*auth\w*|\w*claims|current_?user|\w*jwt\w*|bearer\w*|principal|logged_?in\w*|admin\w*|require\w*|session_?user|user_?session)$",
            ),
            auth_layer: re(
                r"(?i)auth|login|jwt|bearer|guard|permission|require|acl|rbac|access_?control|protect",
            ),
            auth_ident: re(r"(?i)^(?:authorization|bearer|bearer_auth)$"),
            revoke: re(
                r"(?i)revoke|invalidat|logout|purge|cycle_id|token_version|session_version|security_stamp|tokens_valid_after|^renew$|(?:delete|remove|clear|destroy|expire)_?\w*(?:session|token)|(?:session|token)s?_?(?:delete|remove|clear|destroy|expire)",
            ),
            cred_update: re(
                r"(?i)(?:change|reset|update|set|rotate)_?(?:user_?)?password|password_?(?:change|reset|update)",
            ),
            cred_excluded: re(r"(?i)request|forgot|send|email|link|form|page"),
            pw_ctx: re(r"(?i)passw|pwd|passphrase|credential|^pass$"),
            default_cred: re(
                r"(?i)(?:default|initial|temp|fallback|reset|fixed|static|master|admin)\w*(?:passw|pwd|pass\b|passphrase|credential)|(?:passw|pwd)\w*_(?:default|fallback)",
            ),
            not_a_credential: re(
                r"(?i)_(?:env|var|key|name|field|header|len|length|min|max|path|regex|re|label|msg|message)$",
            ),
            public_route: re(
                r"(?i)login|signin|sign_in|logout|register|signup|sign_up|health|ready|live|metrics|forgot|reset|public|webhook|callback|static|assets|favicon|verify_email|confirm",
            ),
            admin_route: re(r"(?i)admin"),
        }
    }
}

struct FnInfo<'a> {
    name: String,
    file: usize,
    sig: &'a syn::Signature,
    block: &'a syn::Block,
    attrs: &'a [Attribute],
    /// Self type when this fn implements `FromRequest` / `FromRequestParts`.
    extractor_of: Option<String>,
    calls: BTreeSet<String>,
    idents: BTreeSet<String>,
    strings: Vec<String>,
}

#[derive(Clone)]
struct Route {
    method: String,
    path: String,
    handler: String,
    guards: Vec<String>,
    file: usize,
    line: u32,
}

#[derive(Clone, Default)]
struct Resolved {
    routes: Vec<Route>,
    wraps: Vec<String>,
    prefix: String,
}

struct Analysis<'a> {
    files: &'a [Parsed],
    rules: Rules,
    fns: Vec<FnInfo<'a>>,
    by_name: HashMap<String, Vec<usize>>,
    /// Non-test `const`/`static` string literals by name.
    consts: HashMap<String, String>,
}

impl<'a> Analysis<'a> {
    fn new(files: &'a [Parsed], rules: Rules) -> Self {
        let mut fns = Vec::new();
        let mut consts = HashMap::new();
        for (i, p) in files.iter().enumerate() {
            let mut c = ItemCollector {
                file: i,
                fns: &mut fns,
                consts: &mut consts,
                impl_extractor: None,
            };
            c.visit_file(&p.ast);
        }
        let mut by_name: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, f) in fns.iter().enumerate() {
            by_name.entry(f.name.clone()).or_default().push(i);
        }
        Self {
            files,
            rules,
            fns,
            by_name,
            consts,
        }
    }

    fn run(&self, perms: Option<&PermissionMap>, mut limits: Vec<String>) -> Vec<Finding> {
        let mut out = self.reset_fallbacks();
        let (routes, mut route_limits) = self.resolve_routes();
        limits.append(&mut route_limits);
        out.extend(self.session_revocation(&routes));
        out.extend(self.missing_auth(&routes, &mut limits));
        if let Some(map) = perms {
            out.extend(self.read_perm_writes(&routes, map));
        }
        out.truncate(MAX_FINDINGS);
        if !limits.is_empty() {
            limits.sort();
            limits.dedup();
            let shown: Vec<_> = limits.iter().take(20).cloned().collect();
            out.push(
                Finding::new(
                    "Rust auth analysis: unsupported or skipped constructs",
                    Severity::Info,
                    "file://.",
                    format!(
                        "{} item(s) could not be analysed; auth findings may be incomplete. {LIMITS}",
                        limits.len()
                    ),
                    "Review the listed files/handlers manually.",
                    PLUGIN,
                )
                .with_source_tool(SOURCE_TOOL)
                .with_parameter("analysis-limits")
                .with_evidence(shown.join("\n"))
                .tentative(),
            );
        }
        out
    }

    // ---------------------------------------------------------------- findings

    fn finding(
        &self,
        at: (usize, u32),
        rule: &str,
        title: &str,
        detail: String,
        evidence: String,
    ) -> Finding {
        let (sev, remediation, cwe, owasp, tentative) = match rule {
            "reset-fallback" => (
                Severity::High,
                "Never fall back to a fixed password; reject the request or generate a random one-time secret and force a change on first login.",
                1393,
                "A07:2021",
                false,
            ),
            "session-not-revoked" => (
                Severity::Medium,
                "Revoke other sessions / refresh tokens (or bump a token version) when credentials change, unless the auth contract already guarantees it.",
                613,
                "A07:2021",
                true,
            ),
            "missing-auth" => (
                Severity::Medium,
                "Protect the route with an auth layer/wrap, an auth extractor, or an explicit check in the handler.",
                306,
                "A01:2021",
                true,
            ),
            _ => (
                Severity::Medium,
                "Require the write permission for state-changing routes.",
                285,
                "A01:2021",
                true,
            ),
        };
        let p = &self.files[at.0];
        let f = Finding::new(
            title,
            sev,
            file_url(&p.path, Some(at.1)),
            format!("{detail} {LIMITS}"),
            remediation,
            PLUGIN,
        )
        .with_source_tool(SOURCE_TOOL)
        .with_parameter(rule)
        .with_evidence(evidence)
        .with_cwe(cwe)
        .with_owasp(owasp)
        .with_location(CodeLocation {
            file: p.rel.clone(),
            line_start: at.1,
            line_end: None,
        });
        if tentative {
            f.tentative()
        } else {
            f
        }
    }

    fn reset_fallbacks(&self) -> Vec<Finding> {
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for f in &self.fns {
            let mut v = FallbackVisitor {
                a: self,
                hits: Vec::new(),
            };
            v.visit_block(f.block);
            for (line, what) in v.hits {
                if seen.insert((f.file, line)) {
                    out.push(self.finding(
                        (f.file, line),
                        "reset-fallback",
                        "Fixed/predictable password fallback",
                        format!(
                            "`{}` falls back to a fixed credential; anyone who knows the default can take over the account.",
                            f.name
                        ),
                        format!("{} -> {what}", f.name),
                    ));
                }
            }
        }
        out
    }

    /// Fixed string value of `e`, if it is a literal or a known constant.
    fn fixed_string(&self, e: &Expr) -> Option<String> {
        match e {
            Expr::Lit(l) => match &l.lit {
                Lit::Str(s) if !s.value().is_empty() => Some(format!("\"{}\"", redact(&s.value()))),
                _ => None,
            },
            Expr::Path(p) => {
                let name = p.path.segments.last()?.ident.to_string();
                let v = self.consts.get(&name)?;
                Some(format!("{name} = \"{}\"", redact(v)))
            }
            Expr::MethodCall(m)
                if matches!(
                    m.method.to_string().as_str(),
                    "to_string" | "to_owned" | "into" | "clone"
                ) =>
            {
                self.fixed_string(&m.receiver)
            }
            Expr::Call(c) if call_name(c).is_some_and(|n| n == "from") && c.args.len() == 1 => {
                self.fixed_string(&c.args[0])
            }
            Expr::Closure(c) => self.fixed_string(&c.body),
            Expr::Block(b) => match b.block.stmts.last() {
                Some(Stmt::Expr(e, None)) => self.fixed_string(e),
                _ => None,
            },
            Expr::Paren(p) => self.fixed_string(&p.expr),
            Expr::Reference(r) => self.fixed_string(&r.expr),
            _ => None,
        }
    }

    fn is_default_cred_const(&self, name: &str) -> bool {
        self.rules.default_cred.is_match(name)
            && !self.rules.not_a_credential.is_match(name)
            && self
                .consts
                .get(name)
                .is_some_and(|v| !v.chars().all(|c| c.is_ascii_uppercase() || c == '_'))
    }

    fn handler_shaped(&self, i: usize, routes: &[Route]) -> bool {
        let f = &self.fns[i];
        actix_route(f.attrs).is_some()
            || routes.iter().any(|r| r.handler == f.name)
            || f.sig.inputs.iter().any(|a| {
                arg_type_idents(a).first().is_some_and(|t| {
                    matches!(
                        t.as_str(),
                        "Json"
                            | "Form"
                            | "Query"
                            | "Path"
                            | "State"
                            | "Data"
                            | "HttpRequest"
                            | "Extension"
                    )
                })
            })
    }

    fn session_revocation(&self, routes: &[Route]) -> Vec<Finding> {
        let mut out = Vec::new();
        for (i, f) in self.fns.iter().enumerate() {
            if f.extractor_of.is_some() || !self.handler_shaped(i, routes) {
                continue;
            }
            let rules = &self.rules;
            if rules.cred_excluded.is_match(&f.name) {
                continue;
            }
            let update = self
                .find_chain(i, &|g| {
                    g.calls
                        .iter()
                        .find(|c| rules.cred_update.is_match(c) && !rules.cred_excluded.is_match(c))
                        .cloned()
                })
                .or_else(|| {
                    rules
                        .cred_update
                        .is_match(&f.name)
                        .then(|| vec![f.name.clone()])
                });
            let Some(update) = update else { continue };
            let revoked = self.find_chain(i, &|g| {
                g.calls
                    .iter()
                    .chain(g.idents.iter())
                    .find(|c| rules.revoke.is_match(c))
                    .cloned()
            });
            if revoked.is_none() {
                out.push(self.finding(
                    (f.file, line_of(f.sig.ident.span())),
                    "session-not-revoked",
                    "Credential update without session/token revocation (review)",
                    format!(
                        "`{}` updates credentials but no session/token invalidation is reachable from it in this crate. Reviewable candidate: the application contract (e.g. short-lived stateless tokens checked against a password timestamp elsewhere) may already cover it.",
                        f.name
                    ),
                    format!("credential update: {}; no revoke/invalidate/purge/token_version call reachable", update.join(" -> ")),
                ));
            }
        }
        out
    }

    fn missing_auth(&self, routes: &[Route], limits: &mut Vec<String>) -> Vec<Finding> {
        let mut groups: BTreeMap<(String, String), Vec<&Route>> = BTreeMap::new();
        for r in routes {
            groups
                .entry((r.handler.clone(), r.method.clone()))
                .or_default()
                .push(r);
        }
        let mut out = Vec::new();
        for ((handler, method), rs) in groups {
            let Some(fns) = self.by_name.get(&handler) else {
                limits.push(format!(
                    "handler `{handler}` not found in crate (cross-crate or macro)"
                ));
                continue;
            };
            let r = rs[0];
            let label = format!("{handler} {}", r.path);
            let sensitive = self.rules.admin_route.is_match(&label)
                || (is_write(&method) && !self.rules.public_route.is_match(&label));
            if !sensitive || rs.iter().any(|r| self.protection(r, fns).is_some()) {
                continue;
            }
            out.push(self.finding(
                (r.file, r.line),
                "missing-auth",
                "Route without authentication/permission check (review)",
                format!(
                    "{} {} -> `{handler}` has no auth layer/wrap, auth extractor, or reachable auth check after resolving route registration and middleware.",
                    method.to_uppercase(),
                    r.path
                ),
                format!(
                    "{} {} -> {handler}; guards: none; extractors: none; reachable auth calls: none",
                    method.to_uppercase(),
                    r.path
                ),
            ));
        }
        out
    }

    fn read_perm_writes(&self, routes: &[Route], map: &PermissionMap) -> Vec<Finding> {
        let quoted = Regex::new(r#""([^"]*)""#).expect("static regex");
        let mut seen = BTreeSet::new();
        let mut out = Vec::new();
        for r in routes.iter().filter(|r| is_write(&r.method)) {
            if !seen.insert((r.handler.clone(), r.method.clone(), r.path.clone())) {
                continue;
            }
            let mut found: BTreeMap<String, String> = BTreeMap::new();
            for g in &r.guards {
                for c in quoted.captures_iter(g) {
                    found.insert(c[1].to_string(), format!("middleware `{g}`"));
                }
            }
            for &i in self.by_name.get(&r.handler).into_iter().flatten() {
                for p in map.read.iter().chain(map.write.iter()) {
                    if let Some(chain) =
                        self.find_chain(i, &|g| g.strings.contains(p).then(|| format!("\"{p}\"")))
                    {
                        found.entry(p.clone()).or_insert(chain.join(" -> "));
                    }
                }
            }
            found.retain(|p, _| map.read.contains(p) || map.write.contains(p));
            if found.is_empty() || found.keys().any(|p| map.write.contains(p)) {
                continue;
            }
            let via: Vec<_> = found.iter().map(|(p, c)| format!("{p} via {c}")).collect();
            out.push(self.finding(
                (r.file, r.line),
                "read-perm-write",
                "Sensitive write guarded only by a read permission",
                format!(
                    "{} {} -> `{}` changes state but only read permission(s) from {PERMISSION_MAP_FILE} guard it.",
                    r.method.to_uppercase(),
                    r.path,
                    r.handler
                ),
                format!("{} {} -> {}; {}", r.method.to_uppercase(), r.path, r.handler, via.join("; ")),
            ));
        }
        out
    }

    // ------------------------------------------------------------ auth model

    fn protection(&self, r: &Route, fns: &[usize]) -> Option<String> {
        if let Some(g) = r.guards.first() {
            return Some(format!("middleware `{g}`"));
        }
        fns.iter().find_map(|&i| {
            self.auth_param(i)
                .or_else(|| self.auth_chain(i).map(|c| c.join(" -> ")))
        })
    }

    fn auth_param(&self, i: usize) -> Option<String> {
        self.fns[i].sig.inputs.iter().find_map(|a| {
            let idents = arg_type_idents(a);
            if idents
                .first()
                .is_some_and(|t| INPUT_WRAPPERS.contains(&t.as_str()))
            {
                return None;
            }
            idents
                .into_iter()
                .find(|t| self.rules.auth_type.is_match(t) || self.custom_auth_extractor(t))
        })
    }

    fn custom_auth_extractor(&self, ty: &str) -> bool {
        self.fns
            .iter()
            .enumerate()
            .any(|(j, f)| f.extractor_of.as_deref() == Some(ty) && self.auth_chain(j).is_some())
    }

    fn auth_chain(&self, i: usize) -> Option<Vec<String>> {
        let rules = &self.rules;
        self.find_chain(i, &|g| {
            g.calls
                .iter()
                .find(|c| rules.auth_call.is_match(c))
                .or_else(|| g.idents.iter().find(|c| rules.auth_ident.is_match(c)))
                .cloned()
        })
    }

    fn is_auth_guard(&self, names: &BTreeSet<String>) -> bool {
        names.iter().any(|n| {
            self.rules.auth_layer.is_match(n)
                || self
                    .by_name
                    .get(n)
                    .is_some_and(|v| v.iter().any(|&j| self.auth_chain(j).is_some()))
        })
    }

    /// BFS over the crate call graph from `start`; returns `[start, .., hit]`.
    fn find_chain(
        &self,
        start: usize,
        pred: &dyn Fn(&FnInfo) -> Option<String>,
    ) -> Option<Vec<String>> {
        let mut seen = BTreeSet::new();
        let mut q = VecDeque::from([(start, vec![self.fns[start].name.clone()])]);
        while let Some((i, chain)) = q.pop_front() {
            if !seen.insert(i) {
                continue;
            }
            let f = &self.fns[i];
            if let Some(hit) = pred(f) {
                let mut c = chain;
                if c.last() != Some(&hit) {
                    c.push(hit);
                }
                return Some(c);
            }
            if chain.len() > MAX_DEPTH {
                continue;
            }
            for callee in &f.calls {
                for &j in self.by_name.get(callee).into_iter().flatten() {
                    let mut c = chain.clone();
                    c.push(callee.clone());
                    q.push_back((j, c));
                }
            }
        }
        None
    }

    // ---------------------------------------------------------------- routes

    fn resolve_routes(&self) -> (Vec<Route>, Vec<String>) {
        let mut res = Resolver {
            a: self,
            file: 0,
            locals: HashMap::new(),
            depth: 0,
            consumed: BTreeSet::new(),
            limits: Vec::new(),
        };
        let mut found: Vec<(String, Route)> = Vec::new();
        for f in &self.fns {
            res.file = f.file;
            res.locals.clear();
            let mut finder = RootFinder {
                res: &mut res,
                out: Vec::new(),
            };
            finder.visit_block(f.block);
            let out = finder.out;
            found.extend(out.into_iter().map(|r| (f.name.clone(), r)));
        }
        let routes: Vec<Route> = found
            .into_iter()
            .filter(|(owner, _)| !res.consumed.contains(owner))
            .map(|(_, r)| r)
            .collect();
        let registered: BTreeSet<&str> = routes.iter().map(|r| r.handler.as_str()).collect();
        for f in &self.fns {
            if actix_route(f.attrs).is_some() && !registered.contains(f.name.as_str()) {
                res.limits.push(format!(
                    "{}: `{}` has a route macro but no resolved `.service(..)` registration",
                    self.files[f.file].rel, f.name
                ));
            }
        }
        (routes, res.limits)
    }
}

struct Resolver<'r, 'a> {
    a: &'r Analysis<'a>,
    file: usize,
    locals: HashMap<String, Resolved>,
    depth: usize,
    consumed: BTreeSet<String>,
    limits: Vec<String>,
}

impl Resolver<'_, '_> {
    fn guard_of(&self, e: &Expr) -> Option<String> {
        let mut s = BodyScan::default();
        s.visit_expr(e);
        self.a
            .is_auth_guard(&s.idents)
            .then(|| short(&e.to_token_stream().to_string()))
    }

    fn resolve(&mut self, e: &Expr) -> Option<Resolved> {
        match e {
            Expr::MethodCall(mc) => {
                let mut r = self.resolve(&mc.receiver)?;
                let args: Vec<&Expr> = mc.args.iter().collect();
                match (mc.method.to_string().as_str(), args.as_slice()) {
                    ("route", [p, mr]) => {
                        let path = format!("{}{}", r.prefix, lit_str(p).unwrap_or_default());
                        self.push_specs(&mut r, &path, mr);
                    }
                    ("route", [mr]) => {
                        let path = r.prefix.clone();
                        self.push_specs(&mut r, &path, mr);
                    }
                    ("to", [h]) => {
                        if let Some(handler) = path_ident(h) {
                            let route = self.route("any", r.prefix.clone(), handler, h, &r.wraps);
                            r.routes.push(route);
                        }
                    }
                    ("service", [s]) => {
                        if let Some(sub) = self.resolve(s) {
                            absorb(&mut r, sub, "");
                        } else if let Some(h) = path_ident(s) {
                            let attr = self.a.by_name.get(&h).and_then(|v| {
                                v.iter().find_map(|&i| actix_route(self.a.fns[i].attrs))
                            });
                            match attr {
                                Some((method, path, attr_wraps)) => {
                                    let mut guards = r.wraps.clone();
                                    guards.extend(
                                        attr_wraps
                                            .into_iter()
                                            .filter(|w| self.a.is_auth_guard(&words(w))),
                                    );
                                    let path = format!("{}{path}", r.prefix);
                                    let route = self.route(&method, path, h, s, &guards);
                                    r.routes.push(route);
                                }
                                None => self.limits.push(format!(
                                    "{}: `.service({h})` target not resolved",
                                    self.a.files[self.file].rel
                                )),
                            }
                        }
                    }
                    ("nest" | "nest_service", [p, s]) => {
                        if let Some(sub) = self.resolve(s) {
                            absorb(&mut r, sub, &lit_str(p).unwrap_or_default());
                        }
                    }
                    ("merge", [s]) => {
                        if let Some(sub) = self.resolve(s) {
                            absorb(&mut r, sub, "");
                        }
                    }
                    ("configure", [s]) => {
                        if let Some(sub) = path_ident(s).and_then(|n| self.resolve_configure(&n)) {
                            absorb(&mut r, sub, "");
                        }
                    }
                    // Axum: a layer only wraps routes registered before it.
                    ("layer" | "route_layer", [l]) => {
                        if let Some(g) = self.guard_of(l) {
                            r.routes.iter_mut().for_each(|rt| rt.guards.push(g.clone()));
                        }
                    }
                    // Actix: wrap/guard covers the whole scope, before and after.
                    ("wrap" | "wrap_fn" | "guard", [l]) => {
                        if let Some(g) = self.guard_of(l) {
                            r.routes.iter_mut().for_each(|rt| rt.guards.push(g.clone()));
                            r.wraps.push(g);
                        }
                    }
                    _ => {}
                }
                Some(r)
            }
            Expr::Call(c) => {
                let Expr::Path(p) = &*c.func else { return None };
                let segs: Vec<String> = p
                    .path
                    .segments
                    .iter()
                    .map(|s| s.ident.to_string())
                    .collect();
                let last = segs.last()?.as_str();
                let prev = segs.len().checked_sub(2).map(|i| segs[i].as_str());
                match (prev, last) {
                    (Some("Router" | "App"), "new") => Some(Resolved::default()),
                    (None | Some("web"), "scope" | "resource") => Some(Resolved {
                        prefix: c.args.first().and_then(lit_str).unwrap_or_default(),
                        ..Default::default()
                    }),
                    _ => self.resolve_fn(last),
                }
            }
            Expr::Path(p) if p.path.segments.len() == 1 => self
                .locals
                .get(&p.path.segments[0].ident.to_string())
                .cloned(),
            Expr::Paren(x) => self.resolve(&x.expr),
            Expr::Group(x) => self.resolve(&x.expr),
            Expr::Reference(x) => self.resolve(&x.expr),
            _ => None,
        }
    }

    fn route(
        &self,
        method: &str,
        path: String,
        handler: String,
        at: &Expr,
        guards: &[String],
    ) -> Route {
        Route {
            method: method.to_string(),
            path,
            handler,
            guards: guards.to_vec(),
            file: self.file,
            line: line_of(at.span()),
        }
    }

    fn push_specs(&mut self, r: &mut Resolved, path: &str, mr: &Expr) {
        for (method, handler, at, mut guards) in self.method_specs(mr) {
            guards.extend(r.wraps.iter().cloned());
            let route = self.route(&method, path.to_string(), handler, at, &guards);
            r.routes.push(route);
        }
    }

    /// `get(h).post(h2)`, `web::post().to(h)`, `get(h).layer(..)`.
    fn method_specs<'e>(&self, e: &'e Expr) -> Vec<(String, String, &'e Expr, Vec<String>)> {
        match e {
            Expr::Call(c) => match (call_name(c), c.args.first()) {
                (Some(m), Some(h)) if METHODS.contains(&m.as_str()) && c.args.len() == 1 => {
                    path_ident(h)
                        .map(|n| (m, n, h, Vec::new()))
                        .into_iter()
                        .collect()
                }
                _ => Vec::new(),
            },
            Expr::MethodCall(mc) => {
                let mut specs = self.method_specs(&mc.receiver);
                let m = mc.method.to_string();
                let arg = mc.args.first().filter(|_| mc.args.len() == 1);
                if let Some(a) = arg {
                    if METHODS.contains(&m.as_str()) {
                        if let Some(n) = path_ident(a) {
                            specs.push((m, n, a, Vec::new()));
                        }
                    } else if m == "to" {
                        if let Some(n) = path_ident(a) {
                            let method = first_method(&mc.receiver).unwrap_or_else(|| "any".into());
                            specs.push((method, n, a, Vec::new()));
                        }
                    } else if matches!(m.as_str(), "layer" | "route_layer" | "wrap") {
                        if let Some(g) = self.guard_of(a) {
                            specs.iter_mut().for_each(|s| s.3.push(g.clone()));
                        }
                    }
                }
                specs
            }
            Expr::Paren(x) => self.method_specs(&x.expr),
            _ => Vec::new(),
        }
    }

    fn router_fn(&self, name: &str) -> Option<usize> {
        self.a
            .by_name
            .get(name)?
            .iter()
            .copied()
            .find(|&i| match &self.a.fns[i].sig.output {
                syn::ReturnType::Type(_, t) => {
                    let mut s = BodyScan::default();
                    s.visit_type(t);
                    s.idents
                        .iter()
                        .any(|n| matches!(n.as_str(), "Router" | "Scope" | "Resource" | "App"))
                }
                syn::ReturnType::Default => false,
            })
    }

    fn enter<T>(&mut self, i: usize, f: impl FnOnce(&mut Self) -> Option<T>) -> Option<T> {
        if self.depth >= MAX_RESOLVE_DEPTH {
            return None;
        }
        let saved = (std::mem::take(&mut self.locals), self.file);
        self.depth += 1;
        self.file = self.a.fns[i].file;
        let out = f(self);
        self.depth -= 1;
        (self.locals, self.file) = saved;
        if out.is_some() {
            self.consumed.insert(self.a.fns[i].name.clone());
        }
        out
    }

    fn resolve_fn(&mut self, name: &str) -> Option<Resolved> {
        let i = self.router_fn(name)?;
        let block = self.a.fns[i].block;
        self.enter(i, |s| {
            let mut tail = None;
            for stmt in &block.stmts {
                match stmt {
                    Stmt::Local(l) => {
                        s.bind_local(l);
                    }
                    Stmt::Expr(Expr::Return(r), _) => {
                        tail = r.expr.as_deref().and_then(|e| s.resolve(e))
                    }
                    Stmt::Expr(e, None) => tail = s.resolve(e),
                    _ => {}
                }
            }
            tail
        })
    }

    /// Actix `fn config(cfg: &mut web::ServiceConfig) { cfg.service(..); }`.
    fn resolve_configure(&mut self, name: &str) -> Option<Resolved> {
        let a = self.a;
        let i = *a.by_name.get(name)?.first()?;
        let f = &a.fns[i];
        let param = f.sig.inputs.iter().find_map(|a| match a {
            FnArg::Typed(pt) => pat_ident(&pt.pat),
            FnArg::Receiver(_) => None,
        })?;
        let block = f.block;
        self.enter(i, |s| {
            s.locals.insert(param, Resolved::default());
            let mut acc = Resolved::default();
            for stmt in &block.stmts {
                if let Stmt::Expr(e, _) = stmt {
                    if let Some(sub) = s.resolve(e) {
                        absorb(&mut acc, sub, "");
                    }
                }
            }
            Some(acc)
        })
    }

    fn bind_local(&mut self, l: &syn::Local) -> Option<Resolved> {
        let name = pat_ident(&l.pat)?;
        let r = self.resolve(&l.init.as_ref()?.expr)?;
        self.locals.insert(name, r.clone());
        Some(r)
    }
}

fn absorb(r: &mut Resolved, sub: Resolved, prefix: &str) {
    for mut rt in sub.routes {
        rt.path = format!("{}{prefix}{}", r.prefix, rt.path);
        rt.guards.extend(r.wraps.iter().cloned());
        r.routes.push(rt);
    }
}

/// Finds maximal router expressions inside one function body.
struct RootFinder<'x, 'r, 'a> {
    res: &'x mut Resolver<'r, 'a>,
    out: Vec<Route>,
}

impl<'ast> Visit<'ast> for RootFinder<'_, '_, '_> {
    fn visit_local(&mut self, l: &'ast syn::Local) {
        match self.res.bind_local(l) {
            Some(r) => self.out.extend(r.routes),
            None => visit::visit_local(self, l),
        }
    }

    fn visit_expr(&mut self, e: &'ast Expr) {
        match self.res.resolve(e) {
            Some(r) => self.out.extend(r.routes),
            None => visit::visit_expr(self, e),
        }
    }

    fn visit_item(&mut self, _: &'ast syn::Item) {}
}

// ------------------------------------------------------------- collection

struct ItemCollector<'c, 'a> {
    file: usize,
    fns: &'c mut Vec<FnInfo<'a>>,
    consts: &'c mut HashMap<String, String>,
    impl_extractor: Option<String>,
}

impl<'a> ItemCollector<'_, 'a> {
    fn push_fn(&mut self, attrs: &'a [Attribute], sig: &'a syn::Signature, block: &'a syn::Block) {
        let mut s = BodyScan::default();
        s.visit_block(block);
        self.fns.push(FnInfo {
            name: sig.ident.to_string(),
            file: self.file,
            sig,
            block,
            attrs,
            extractor_of: self.impl_extractor.clone(),
            calls: s.calls,
            idents: s.idents,
            strings: s.strings,
        });
    }

    fn push_const(&mut self, attrs: &[Attribute], ident: &syn::Ident, e: &Expr) {
        if let (false, Expr::Lit(l)) = (is_test(attrs), e) {
            if let Lit::Str(s) = &l.lit {
                self.consts.insert(ident.to_string(), s.value());
            }
        }
    }
}

impl<'a> Visit<'a> for ItemCollector<'_, 'a> {
    fn visit_item_mod(&mut self, m: &'a syn::ItemMod) {
        if !is_test(&m.attrs) {
            visit::visit_item_mod(self, m);
        }
    }

    fn visit_item_fn(&mut self, f: &'a syn::ItemFn) {
        if !is_test(&f.attrs) {
            self.push_fn(&f.attrs, &f.sig, &f.block);
            visit::visit_item_fn(self, f);
        }
    }

    fn visit_item_impl(&mut self, i: &'a syn::ItemImpl) {
        if is_test(&i.attrs) {
            return;
        }
        let is_extractor = i.trait_.as_ref().is_some_and(|(_, p, _)| {
            p.segments
                .last()
                .is_some_and(|s| s.ident == "FromRequest" || s.ident == "FromRequestParts")
        });
        let saved = self.impl_extractor.take();
        if is_extractor {
            let mut s = BodyScan::default();
            s.visit_type(&i.self_ty);
            self.impl_extractor = s.last_ident;
        }
        visit::visit_item_impl(self, i);
        self.impl_extractor = saved;
    }

    fn visit_impl_item_fn(&mut self, f: &'a syn::ImplItemFn) {
        if !is_test(&f.attrs) {
            self.push_fn(&f.attrs, &f.sig, &f.block);
            visit::visit_impl_item_fn(self, f);
        }
    }

    fn visit_item_const(&mut self, c: &'a syn::ItemConst) {
        self.push_const(&c.attrs, &c.ident, &c.expr);
    }

    fn visit_item_static(&mut self, c: &'a syn::ItemStatic) {
        self.push_const(&c.attrs, &c.ident, &c.expr);
    }
}

#[derive(Default)]
struct BodyScan {
    calls: BTreeSet<String>,
    idents: BTreeSet<String>,
    strings: Vec<String>,
    last_ident: Option<String>,
}

impl<'a> Visit<'a> for BodyScan {
    fn visit_expr_call(&mut self, c: &'a syn::ExprCall) {
        if let Some(n) = call_name(c) {
            self.calls.insert(n);
        }
        visit::visit_expr_call(self, c);
    }

    fn visit_expr_method_call(&mut self, m: &'a syn::ExprMethodCall) {
        self.calls.insert(m.method.to_string());
        visit::visit_expr_method_call(self, m);
    }

    fn visit_ident(&mut self, i: &'a syn::Ident) {
        self.idents.insert(i.to_string());
        self.last_ident = Some(i.to_string());
    }

    fn visit_lit_str(&mut self, s: &'a syn::LitStr) {
        self.strings.push(s.value());
    }
}

struct FallbackVisitor<'v, 'a> {
    a: &'v Analysis<'a>,
    hits: Vec<(u32, String)>,
}

impl<'ast> Visit<'ast> for FallbackVisitor<'_, '_> {
    fn visit_expr_method_call(&mut self, m: &'ast syn::ExprMethodCall) {
        let method = m.method.to_string();
        if matches!(method.as_str(), "unwrap_or" | "unwrap_or_else") && m.args.len() == 1 {
            if let Some(value) = self.a.fixed_string(&m.args[0]) {
                let mut recv = BodyScan::default();
                recv.visit_expr(&m.receiver);
                let rules = &self.a.rules;
                let pw = recv
                    .idents
                    .iter()
                    .chain(recv.strings.iter())
                    .any(|s| rules.pw_ctx.is_match(s));
                let const_name = value.split(" = ").next().unwrap_or_default();
                if pw || self.a.is_default_cred_const(const_name) {
                    self.hits
                        .push((line_of(m.method.span()), format!(".{method}({value})")));
                }
            }
        }
        visit::visit_expr_method_call(self, m);
    }

    fn visit_expr_path(&mut self, p: &'ast syn::ExprPath) {
        if let Some(seg) = p.path.segments.last() {
            let name = seg.ident.to_string();
            if self.a.is_default_cred_const(&name) {
                let v = self
                    .a
                    .consts
                    .get(&name)
                    .map(|v| redact(v))
                    .unwrap_or_default();
                self.hits.push((
                    line_of(seg.ident.span()),
                    format!("{name} = \"{v}\" (hardcoded default credential)"),
                ));
            }
        }
    }

    fn visit_item(&mut self, _: &'ast syn::Item) {}
}

// ---------------------------------------------------------------- helpers

fn is_test(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| {
        let last = a.path().segments.last().map(|s| s.ident.to_string());
        if last.as_deref() == Some("test") {
            return true;
        }
        if !a.path().is_ident("cfg") {
            return false;
        }
        let toks = match &a.meta {
            syn::Meta::List(l) => l.tokens.to_string(),
            _ => return false,
        };
        toks.contains("test") && !toks.contains("not")
    })
}

/// `#[get("/p")]`, `#[route("/p", method = "POST")]`, `wrap = ".."` â†’ (method, path, wraps).
fn actix_route(attrs: &[Attribute]) -> Option<(String, String, Vec<String>)> {
    attrs.iter().find_map(|a| {
        let name = a.path().segments.last()?.ident.to_string();
        if !(METHODS.contains(&name.as_str()) || name == "route") {
            return None;
        }
        let args = a
            .parse_args_with(Punctuated::<Expr, syn::Token![,]>::parse_terminated)
            .ok()?;
        let (mut path, mut method, mut wraps) = (None, name, Vec::new());
        for e in &args {
            match e {
                Expr::Assign(x) => {
                    let (Some(k), Some(v)) = (path_ident(&x.left), lit_str(&x.right)) else {
                        continue;
                    };
                    match k.as_str() {
                        "method" => method = v.to_lowercase(),
                        "wrap" | "guard" => wraps.push(v),
                        _ => {}
                    }
                }
                other => path = path.or_else(|| lit_str(other)),
            }
        }
        Some((method, path?, wraps))
    })
}

fn call_name(c: &syn::ExprCall) -> Option<String> {
    match &*c.func {
        Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

fn first_method(e: &Expr) -> Option<String> {
    match e {
        Expr::Call(c) if c.args.is_empty() => {
            call_name(c).filter(|m| METHODS.contains(&m.as_str()))
        }
        Expr::MethodCall(mc) => first_method(&mc.receiver),
        _ => None,
    }
}

fn path_ident(e: &Expr) -> Option<String> {
    match e {
        Expr::Path(p) => p.path.segments.last().map(|s| s.ident.to_string()),
        _ => None,
    }
}

fn pat_ident(p: &Pat) -> Option<String> {
    match p {
        Pat::Ident(i) => Some(i.ident.to_string()),
        Pat::Type(t) => pat_ident(&t.pat),
        _ => None,
    }
}

fn lit_str(e: &Expr) -> Option<String> {
    match e {
        Expr::Lit(l) => match &l.lit {
            Lit::Str(s) => Some(s.value()),
            _ => None,
        },
        _ => None,
    }
}

/// Type idents of a handler argument, outermost first (`Extension<Claims>` â†’ [Extension, Claims]).
fn arg_type_idents(a: &FnArg) -> Vec<String> {
    let FnArg::Typed(pt) = a else {
        return Vec::new();
    };
    let ty: &Type = match &*pt.ty {
        Type::Reference(r) => &r.elem,
        t => t,
    };
    let Type::Path(tp) = ty else {
        return Vec::new();
    };
    let Some(last) = tp.path.segments.last() else {
        return Vec::new();
    };
    let mut s = BodyScan::default();
    s.visit_path_arguments(&last.arguments);
    std::iter::once(last.ident.to_string())
        .chain(s.idents)
        .collect()
}

fn words(s: &str) -> BTreeSet<String> {
    s.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .map(str::to_string)
        .collect()
}

fn is_write(method: &str) -> bool {
    matches!(method, "post" | "put" | "patch" | "delete" | "any")
}

fn line_of(span: proc_macro2::Span) -> u32 {
    span.start().line as u32
}

fn short(s: &str) -> String {
    if s.chars().count() > 120 {
        format!("{}â€¦", s.chars().take(120).collect::<String>())
    } else {
        s.to_string()
    }
}

fn redact(s: &str) -> String {
    if s.chars().count() <= 4 {
        "[REDACTED]".to_string()
    } else {
        format!("{}â€¦[REDACTED]", s.chars().take(3).collect::<String>())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan_src(src: &str, perms: Option<&PermissionMap>) -> Vec<Finding> {
        static N: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("rz-rust-auth-{}-{n}", std::process::id()));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        let file = dir.join("src/main.rs");
        std::fs::write(&file, src).unwrap();
        let out = scan_with_permissions(&dir, &[file], perms);
        let _ = std::fs::remove_dir_all(&dir);
        out
    }

    fn rules(f: &[Finding]) -> Vec<&str> {
        f.iter().filter_map(|f| f.parameter.as_deref()).collect()
    }

    #[test]
    fn unparsable_file_is_recorded_not_panicking() {
        let f = scan_src("fn broken( {", None);
        assert_eq!(rules(&f), vec!["analysis-limits"]);
        assert!(f[0].evidence.as_deref().unwrap().contains("not parsed"));
    }

    #[test]
    fn fallback_literal_fires_and_test_module_does_not() {
        let src = r#"
fn reset(new_password: Option<String>) -> String { new_password.unwrap_or("Welcome123".to_string()) }
#[cfg(test)]
mod tests { fn t(password: Option<&str>) -> &str { password.unwrap_or("Welcome123") } }
"#;
        let f = scan_src(src, None);
        let hits: Vec<_> = f
            .iter()
            .filter(|f| f.parameter.as_deref() == Some("reset-fallback"))
            .collect();
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].location.as_ref().unwrap().line_start, 2);
        assert!(!hits[0].evidence.as_deref().unwrap().contains("Welcome123"));
    }

    #[test]
    fn non_password_fallback_and_required_env_are_quiet() {
        let src = r#"
fn reset_page(lang: Option<String>) -> String {
    let _pw = std::env::var("INITIAL_PASSWORD").expect("INITIAL_PASSWORD must be set");
    lang.unwrap_or("en".to_string())
}
"#;
        assert!(rules(&scan_src(src, None)).is_empty());
    }

    #[test]
    fn permission_check_skipped_without_map() {
        let src = r#"
async fn delete_order(user: AuthUser) { require_permission(&user, "orders:read"); }
fn app() { let app = Router::new().route("/orders", delete(delete_order)); }
"#;
        assert!(!rules(&scan_src(src, None)).contains(&"read-perm-write"));
        let map = PermissionMap {
            read: ["orders:read".to_string()].into(),
            write: ["orders:write".to_string()].into(),
        };
        assert!(rules(&scan_src(src, Some(&map))).contains(&"read-perm-write"));
    }
}
