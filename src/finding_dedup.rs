//! Collapse identical findings across routes into one finding with `instances`.
//!
//! "Identical" = same `plugin` + `title` + `severity` (e.g. "Missing CSP" on 17
//! URLs). The first occurrence is kept as the primary finding; when more than
//! one occurrence exists, `instances` lists every distinct location (primary
//! included). Single findings are left untouched so their JSON is unchanged.

use std::collections::HashMap;
use std::hash::Hash;

use crate::types::Finding;

/// One human-readable location string for a finding occurrence.
fn instance_of(f: &Finding) -> String {
    match &f.parameter {
        Some(p) if !p.is_empty() => format!("{} [{}]", f.url, p),
        _ => f.url.clone(),
    }
}

pub fn collapse(findings: Vec<Finding>) -> Vec<Finding> {
    collapse_by(findings, |f| {
        (f.plugin.clone(), f.title.clone(), f.severity.clone())
    })
}

/// [`collapse`] with a caller-chosen identity, e.g. one advisory ID across
/// image and lockfile results (#19). The first occurrence stays primary.
pub fn collapse_by<K: Hash + Eq>(
    findings: Vec<Finding>,
    key: impl Fn(&Finding) -> K,
) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::with_capacity(findings.len());
    let mut index: HashMap<K, usize> = HashMap::new();
    for f in findings {
        let key = key(&f);
        match index.get(&key) {
            Some(&i) => {
                let primary = &mut out[i];
                if primary.instances.is_empty() {
                    primary.instances.push(instance_of(primary));
                }
                // Already-collapsed input (e.g. re-loaded report) carries its own list.
                let extra = if f.instances.is_empty() {
                    vec![instance_of(&f)]
                } else {
                    f.instances
                };
                for inst in extra {
                    if !primary.instances.contains(&inst) {
                        primary.instances.push(inst);
                    }
                }
                for id in f.correlated_with {
                    if !primary.correlated_with.contains(&id) {
                        primary.correlated_with.push(id);
                    }
                }
            }
            None => {
                index.insert(key, out.len());
                out.push(f);
            }
        }
    }
    // A primary whose duplicates all shared its exact location gains nothing.
    for f in &mut out {
        if f.instances.len() == 1 {
            f.instances.clear();
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Severity;

    fn mk(title: &str, sev: Severity, url: &str) -> Finding {
        Finding::new(title, sev, url, "d", "s", "passive/missing-headers")
    }

    #[test]
    fn collapses_same_plugin_title_severity() {
        let input = (0..17)
            .map(|i| mk("Missing CSP", Severity::Medium, &format!("https://x/{i}")))
            .chain([mk("Missing HSTS", Severity::Low, "https://x/0")])
            .collect();
        let out = collapse(input);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].url, "https://x/0");
        assert_eq!(out[0].instances.len(), 17);
        assert_eq!(out[0].instances[16], "https://x/16");
        assert!(out[1].instances.is_empty());
    }

    #[test]
    fn different_severity_or_plugin_stays_separate() {
        let mut other = mk("Missing CSP", Severity::Medium, "https://x/b");
        other.plugin = "passive/other".into();
        let out = collapse(vec![
            mk("Missing CSP", Severity::Medium, "https://x/a"),
            mk("Missing CSP", Severity::High, "https://x/a"),
            other,
        ]);
        assert_eq!(out.len(), 3);
        assert!(out.iter().all(|f| f.instances.is_empty()));
    }

    #[test]
    fn same_location_duplicates_do_not_create_instances() {
        let out = collapse(vec![
            mk("Missing CSP", Severity::Medium, "https://x/a"),
            mk("Missing CSP", Severity::Medium, "https://x/a"),
        ]);
        assert_eq!(out.len(), 1);
        assert!(out[0].instances.is_empty());
    }

    #[test]
    fn instances_round_trip_and_old_json_deserializes() {
        let out = collapse(vec![
            mk("Missing CSP", Severity::Medium, "https://x/a"),
            mk("Missing CSP", Severity::Medium, "https://x/b").with_parameter("q"),
        ]);
        let json = serde_json::to_string(&out[0]).unwrap();
        assert!(json.contains("\"instances\":[\"https://x/a\",\"https://x/b [q]\"]"));
        // Single finding: field omitted, and JSON without it still parses.
        let single = serde_json::to_string(&mk("t", Severity::Low, "u")).unwrap();
        assert!(!single.contains("instances"));
        let back: Finding = serde_json::from_str(&single).unwrap();
        assert!(back.instances.is_empty());
    }
}
