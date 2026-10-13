//! SBOM license policy with origin scoping (issue #20).
//!
//! A CycloneDX license gate that failed on *base-OS* packages (`bash`, `apt`,
//! fonts, …) flagged for strong copyleft drowns the signal that matters — the
//! license posture of the application's *own* dependencies. Base-OS GPL packages
//! shipped in a container under **mere aggregation** do not impose copyleft on
//! the application, so this module classifies every component by origin
//! (application dependency vs OS/distro system package) and applies the policy to
//! a chosen **scope**:
//!
//! - `--license-scope app` (default): Deny/Review is enforced on application
//!   dependencies only; OS/distro packages are reported informationally.
//! - `--license-scope all`: the policy is enforced on everything.
//!
//! An OS-package allowlist file can additionally exempt specific packages, and
//! the report is split into "Application dependencies" vs "Base image / OS".

use std::collections::HashSet;

use anyhow::{Context, Result};
use serde_json::Value;

/// Where a component comes from.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Origin {
    /// The application's own dependency (cargo, npm, pypi, go, …).
    App,
    /// A base-image / distro system package (deb, rpm, apk, …).
    Os,
}

/// Policy verdict for a license. Ordered least → most severe so the worst
/// license of a component can be taken with `max()`.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Verdict {
    Allow,
    Unknown,
    Review,
    Deny,
}

impl Verdict {
    pub fn label(self) -> &'static str {
        match self {
            Verdict::Allow => "ALLOW",
            Verdict::Unknown => "UNKNOWN",
            Verdict::Review => "REVIEW",
            Verdict::Deny => "DENY",
        }
    }
}

/// Which components the policy is enforced on.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LicenseScope {
    /// Application dependencies only (default). OS packages are informational.
    App,
    /// Every component.
    All,
}

impl LicenseScope {
    pub fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "app" | "application" => Ok(LicenseScope::App),
            "all" | "everything" => Ok(LicenseScope::All),
            other => anyhow::bail!("unknown --license-scope '{other}' (use 'app' or 'all')"),
        }
    }
}

/// One SBOM component with the fields the policy needs.
#[derive(Clone, Debug)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub licenses: Vec<String>,
    pub origin: Origin,
    pub purl: Option<String>,
}

/// A component plus how the policy treats it.
#[derive(Clone, Debug)]
pub struct ComponentVerdict {
    pub component: Component,
    /// The raw license verdict, independent of scope.
    pub raw: Verdict,
    /// Exempted by the allowlist.
    pub allowlisted: bool,
    /// Whether this component's verdict counts toward the gate (in scope and not
    /// allowlisted). When false, a Deny/Review is informational only.
    pub enforced: bool,
}

impl ComponentVerdict {
    /// Fails the build gate: in scope, not allowlisted, and denied.
    pub fn is_blocking(&self) -> bool {
        self.enforced && self.raw == Verdict::Deny
    }
}

/// The scoped, split report.
#[derive(Debug)]
pub struct ScopedReport {
    pub scope: LicenseScope,
    pub app: Vec<ComponentVerdict>,
    pub os: Vec<ComponentVerdict>,
}

impl ScopedReport {
    /// Count of components that fail the gate (enforced denies).
    pub fn blocking_count(&self) -> usize {
        self.app
            .iter()
            .chain(self.os.iter())
            .filter(|c| c.is_blocking())
            .count()
    }

    pub fn has_blocking_denies(&self) -> bool {
        self.blocking_count() > 0
    }
}

/// Map a single license identifier/name to a policy verdict.
///
/// Order matters: weak-copyleft names (LGPL, …) are matched before the strong
/// `GPL` prefix, because their names contain "GPL".
pub fn license_verdict(license: &str) -> Verdict {
    let u = license.trim().to_ascii_uppercase();
    if u.is_empty() || u == "NOASSERTION" || u == "NONE" {
        return Verdict::Unknown;
    }

    // Weak copyleft / review-required — must precede the GPL check.
    const REVIEW: &[&str] = &[
        "LGPL", "MPL", "EPL", "CDDL", "CPL", "MS-PL", "MS-RL", "EUPL", "CECILL", "APSL", "QPL",
    ];
    if REVIEW.iter().any(|&p| u.starts_with(p)) {
        return Verdict::Review;
    }

    // Strong / network copyleft and commercial-unfriendly — denied by default.
    const DENY: &[&str] = &[
        "AGPL",
        "GPL",
        "SSPL",
        "OSL",
        "CPAL",
        "RPL",
        "EUPL-1.2",
        "SLEEPYCAT",
        "GFDL",
        "WATCOM",
        "PARITY",
        "COMMONS-CLAUSE",
        "BUSL",
    ];
    if DENY.iter().any(|&p| u.starts_with(p)) {
        return Verdict::Deny;
    }

    // Permissive.
    const ALLOW: &[&str] = &[
        "MIT",
        "APACHE",
        "BSD",
        "ISC",
        "ZLIB",
        "0BSD",
        "UNLICENSE",
        "CC0",
        "BSL",
        "BOOST",
        "PYTHON",
        "PSF",
        "WTFPL",
        "NCSA",
        "ARTISTIC",
        "UPL",
        "MPL-1.0-PERMISSIVE",
    ];
    if ALLOW.iter().any(|&p| u.starts_with(p)) || u.contains("PUBLIC DOMAIN") || u == "CC-BY-4.0" {
        return Verdict::Allow;
    }

    Verdict::Unknown
}

/// Worst-case verdict across all of a component's licenses.
pub fn component_verdict(c: &Component) -> Verdict {
    c.licenses
        .iter()
        .map(|l| license_verdict(l))
        .max()
        .unwrap_or(Verdict::Unknown)
}

/// Classify a component's origin from its purl type, falling back to Trivy
/// `PkgType`/`Class` properties.
pub fn classify_origin(purl: Option<&str>, raw: &Value) -> Origin {
    const OS_PURL_TYPES: &[&str] = &[
        "deb", "rpm", "apk", "alpine", "suse", "arch", "ebuild", "portage", "nix", "swid",
    ];
    if let Some(p) = purl {
        if let Some(rest) = p.strip_prefix("pkg:") {
            let ptype = rest.split('/').next().unwrap_or("").to_ascii_lowercase();
            return if OS_PURL_TYPES.contains(&ptype.as_str()) {
                Origin::Os
            } else {
                Origin::App
            };
        }
    }

    // Fallbacks for SBOMs without a purl: Trivy tags OS packages via properties.
    const OS_PKG_VALUES: &[&str] = &[
        "os-pkgs", "debian", "ubuntu", "redhat", "rocky", "centos", "alpine", "amazon", "oracle",
        "photon", "suse", "opensuse", "mariner",
    ];
    if let Some(props) = raw.get("properties").and_then(|v| v.as_array()) {
        for pr in props {
            let key = pr.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let val = pr
                .get("value")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            if (key.ends_with("PkgType") || key.ends_with("Class"))
                && OS_PKG_VALUES.contains(&val.as_str())
            {
                return Origin::Os;
            }
        }
    }
    if raw.get("type").and_then(|v| v.as_str()) == Some("operating-system") {
        return Origin::Os;
    }

    Origin::App
}

fn extract_licenses(c: &Value) -> Vec<String> {
    let mut out = Vec::new();
    let Some(arr) = c.get("licenses").and_then(|v| v.as_array()) else {
        return out;
    };
    for l in arr {
        if let Some(id) = l
            .get("license")
            .and_then(|lic| lic.get("id"))
            .and_then(|v| v.as_str())
        {
            out.push(id.to_string());
        } else if let Some(name) = l
            .get("license")
            .and_then(|lic| lic.get("name"))
            .and_then(|v| v.as_str())
        {
            out.push(name.to_string());
        } else if let Some(expr) = l.get("expression").and_then(|v| v.as_str()) {
            // Split an SPDX expression ("MIT OR Apache-2.0") into its ids.
            for tok in expr.split(|ch: char| ch.is_whitespace() || ch == '(' || ch == ')') {
                let t = tok.trim();
                if !t.is_empty()
                    && !matches!(t.to_ascii_uppercase().as_str(), "OR" | "AND" | "WITH")
                {
                    out.push(t.to_string());
                }
            }
        }
    }
    out
}

/// Parse a CycloneDX JSON SBOM into components.
pub fn parse_cyclonedx(json: &str) -> Result<Vec<Component>> {
    let doc: Value = serde_json::from_str(json).context("parse CycloneDX JSON")?;
    let comps = doc
        .get("components")
        .and_then(|c| c.as_array())
        .context("CycloneDX document has no 'components' array")?;

    let mut out = Vec::new();
    for c in comps {
        let name = c
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            continue;
        }
        let version = c
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let purl = c.get("purl").and_then(|v| v.as_str()).map(String::from);
        let licenses = extract_licenses(c);
        let origin = classify_origin(purl.as_deref(), c);
        out.push(Component {
            name,
            version,
            licenses,
            origin,
            purl,
        });
    }
    Ok(out)
}

/// Load an allowlist file: one package name per line, `#` comments and blanks
/// ignored. Names are matched case-insensitively.
pub fn load_allowlist(path: Option<&str>) -> Result<HashSet<String>> {
    let mut set = HashSet::new();
    let Some(path) = path else { return Ok(set) };
    let text =
        std::fs::read_to_string(path).with_context(|| format!("read allowlist file {path}"))?;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        set.insert(l.to_ascii_lowercase());
    }
    Ok(set)
}

/// Apply the policy to components under `scope`, honoring the allowlist.
pub fn evaluate(
    components: Vec<Component>,
    scope: LicenseScope,
    allowlist: &HashSet<String>,
) -> ScopedReport {
    let mut app = Vec::new();
    let mut os = Vec::new();
    for component in components {
        let raw = component_verdict(&component);
        let allowlisted = allowlist.contains(&component.name.to_ascii_lowercase());
        let in_scope = scope == LicenseScope::All || component.origin == Origin::App;
        let enforced = in_scope && !allowlisted;
        let cv = ComponentVerdict {
            raw,
            allowlisted,
            enforced,
            component,
        };
        match cv.component.origin {
            Origin::App => app.push(cv),
            Origin::Os => os.push(cv),
        }
    }
    ScopedReport { scope, app, os }
}

fn section(title: &str, items: &[ComponentVerdict], enforced_note: &str) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let (mut deny, mut review, mut unknown, mut allow) = (0, 0, 0, 0);
    for c in items {
        match c.raw {
            Verdict::Deny => deny += 1,
            Verdict::Review => review += 1,
            Verdict::Unknown => unknown += 1,
            Verdict::Allow => allow += 1,
        }
    }
    let _ = writeln!(s, "{title} ({} components) — {enforced_note}", items.len());
    let _ = writeln!(
        s,
        "  DENY: {deny}   REVIEW: {review}   UNKNOWN: {unknown}   ALLOW: {allow}"
    );
    // List the actionable ones (Deny/Review), worst first.
    let mut flagged: Vec<&ComponentVerdict> = items
        .iter()
        .filter(|c| c.raw == Verdict::Deny || c.raw == Verdict::Review)
        .collect();
    flagged.sort_by(|a, b| {
        b.raw
            .cmp(&a.raw)
            .then(a.component.name.cmp(&b.component.name))
    });
    for c in flagged {
        let gate = if c.allowlisted {
            " [allowlisted]"
        } else if c.enforced {
            " [enforced]"
        } else {
            " [informational — mere aggregation]"
        };
        let lic = if c.component.licenses.is_empty() {
            "no license metadata".to_string()
        } else {
            c.component.licenses.join(", ")
        };
        let _ = writeln!(
            s,
            "    {:<8} {}@{}  ({}){}",
            c.raw.label(),
            c.component.name,
            c.component.version,
            lic,
            gate
        );
    }
    s
}

/// Render the split, scoped text report.
pub fn render_report(report: &ScopedReport) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let scope = match report.scope {
        LicenseScope::App => "app (application dependencies only)",
        LicenseScope::All => "all (application + OS/base-image)",
    };
    let _ = writeln!(s, "License policy report — scope: {scope}\n");
    s.push_str(&section(
        "Application dependencies",
        &report.app,
        "policy enforced",
    ));
    s.push('\n');
    let os_note = match report.scope {
        LicenseScope::App => "informational (mere aggregation — not gated)",
        LicenseScope::All => "policy enforced",
    };
    s.push_str(&section("Base image / OS packages", &report.os, os_note));
    s.push('\n');
    let blocking = report.blocking_count();
    if blocking == 0 {
        let _ = writeln!(s, "Verdict: PASS (no enforced DENY licenses in scope)");
    } else {
        let _ = writeln!(
            s,
            "Verdict: FAIL ({blocking} enforced DENY license(s) in scope)"
        );
    }
    s
}

/// CLI entry point: parse the SBOM, apply the scoped policy, print the report,
/// and (when `fail_on_deny`) return an error if the gate fails.
pub fn run_license_check(
    sbom_path: &str,
    scope: LicenseScope,
    os_allowlist_path: Option<&str>,
    fail_on_deny: bool,
) -> Result<()> {
    let json = std::fs::read_to_string(sbom_path)
        .with_context(|| format!("read SBOM file {sbom_path}"))?;
    let components = parse_cyclonedx(&json)?;
    let allowlist = load_allowlist(os_allowlist_path)?;
    let report = evaluate(components, scope, &allowlist);
    println!("{}", render_report(&report));
    if fail_on_deny && report.has_blocking_denies() {
        anyhow::bail!(
            "license gate failed: {} enforced DENY license(s) in scope",
            report.blocking_count()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn weak_copyleft_is_review_not_deny() {
        assert_eq!(license_verdict("LGPL-2.1"), Verdict::Review);
        assert_eq!(license_verdict("LGPL-3.0-or-later"), Verdict::Review);
        assert_eq!(license_verdict("MPL-2.0"), Verdict::Review);
    }

    #[test]
    fn strong_copyleft_is_deny() {
        assert_eq!(license_verdict("GPL-2.0-only"), Verdict::Deny);
        assert_eq!(license_verdict("GPL-3.0-or-later"), Verdict::Deny);
        assert_eq!(license_verdict("AGPL-3.0"), Verdict::Deny);
    }

    #[test]
    fn permissive_is_allow() {
        for l in ["MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "0BSD"] {
            assert_eq!(license_verdict(l), Verdict::Allow, "{l}");
        }
    }

    #[test]
    fn origin_from_purl() {
        let nil = Value::Null;
        assert_eq!(
            classify_origin(Some("pkg:deb/debian/bash@5.1"), &nil),
            Origin::Os
        );
        assert_eq!(
            classify_origin(Some("pkg:apk/alpine/musl@1.2"), &nil),
            Origin::Os
        );
        assert_eq!(
            classify_origin(Some("pkg:cargo/serde@1.0"), &nil),
            Origin::App
        );
        assert_eq!(
            classify_origin(Some("pkg:npm/left-pad@1.3"), &nil),
            Origin::App
        );
    }

    #[test]
    fn app_scope_does_not_gate_os_gpl() {
        // A base-OS GPL package must not fail the gate in the default app scope.
        let json = r#"{
          "bomFormat": "CycloneDX",
          "components": [
            {"name": "bash", "version": "5.1", "purl": "pkg:deb/debian/bash@5.1",
             "licenses": [{"license": {"id": "GPL-3.0-or-later"}}]},
            {"name": "serde", "version": "1.0", "purl": "pkg:cargo/serde@1.0",
             "licenses": [{"license": {"id": "MIT"}}]}
          ]
        }"#;
        let comps = parse_cyclonedx(json).unwrap();
        let report = evaluate(comps, LicenseScope::App, &HashSet::new());
        assert_eq!(report.os.len(), 1);
        assert_eq!(report.app.len(), 1);
        // OS GPL is present but NOT enforced (informational), so the gate passes.
        assert!(!report.has_blocking_denies());
        let os_bash = &report.os[0];
        assert_eq!(os_bash.raw, Verdict::Deny);
        assert!(!os_bash.enforced);
    }

    #[test]
    fn all_scope_gates_os_gpl() {
        let json = r#"{
          "components": [
            {"name": "bash", "version": "5.1", "purl": "pkg:deb/debian/bash@5.1",
             "licenses": [{"license": {"id": "GPL-3.0-or-later"}}]}
          ]
        }"#;
        let comps = parse_cyclonedx(json).unwrap();
        let report = evaluate(comps, LicenseScope::All, &HashSet::new());
        assert!(report.has_blocking_denies());
    }

    #[test]
    fn app_gpl_dependency_is_gated_and_allowlist_exempts_it() {
        let json = r#"{
          "components": [
            {"name": "copyleft-crate", "version": "0.1", "purl": "pkg:cargo/copyleft-crate@0.1",
             "licenses": [{"license": {"id": "GPL-3.0-only"}}]}
          ]
        }"#;
        let comps = parse_cyclonedx(json).unwrap();
        let report = evaluate(comps.clone(), LicenseScope::App, &HashSet::new());
        assert!(report.has_blocking_denies());

        let mut allow = HashSet::new();
        allow.insert("copyleft-crate".to_string());
        let report2 = evaluate(comps, LicenseScope::App, &allow);
        assert!(!report2.has_blocking_denies());
        assert!(report2.app[0].allowlisted);
    }

    #[test]
    fn spdx_expression_is_split() {
        let c: Value =
            serde_json::from_str(r#"{"licenses": [{"expression": "MIT OR Apache-2.0"}]}"#).unwrap();
        let lics = extract_licenses(&c);
        assert!(lics.contains(&"MIT".to_string()));
        assert!(lics.contains(&"Apache-2.0".to_string()));
    }
}
