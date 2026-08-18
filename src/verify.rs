//! Evidence & verification primitives — the anti-"self-validation" layer.
//!
//! A professional scanner never concludes a vulnerability exists just because
//! a payload *might* have worked. Every active finding must be backed by
//! evidence that the payload — and not the page's normal content — caused the
//! observed behavior. These helpers provide the three techniques ZAP/Burp use:
//!
//!   1. **Unique canaries** — inject a random token so a match cannot come from
//!      unrelated page text (`rand_token`).
//!   2. **Baseline differential** — fetch the untouched URL once, then only
//!      trust a signature/marker that is present in the payload response but
//!      *absent* from the baseline (`Baseline`, `signature_is_new`).
//!   3. **Content similarity** — quantify how much two responses differ so
//!      boolean-blind logic compares behavior instead of guessing at byte
//!      counts (`body_similarity`).
//!
//! Findings confirmed through these helpers set `Finding::poc_validated = true`
//! and carry `Confidence::Confirmed`; anything weaker is reported honestly as
//! `Tentative` so downstream consumers can triage instead of trusting blindly.

use std::time::Duration;

/// One untouched request/response for a target URL, used as the control in a
/// differential comparison. Fetched once per plugin invocation.
#[derive(Debug, Clone)]
pub struct Baseline {
    pub status: u16,
    pub body: String,
    pub body_lower: String,
    pub len: usize,
}

impl Baseline {
    /// Fetch the target URL as-is to establish control behavior. Returns
    /// `None` on transport error so callers can bail rather than guess.
    pub async fn fetch(client: &reqwest::Client, url: &str) -> Option<Baseline> {
        let resp = client
            .get(url)
            .timeout(Duration::from_secs(8))
            .send()
            .await
            .ok()?;
        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();
        let body_lower = body.to_lowercase();
        let len = body.len();
        Some(Baseline {
            status,
            body,
            body_lower,
            len,
        })
    }
}

/// A random alphanumeric canary token of `len` chars. Injected payloads embed
/// this so a reflection cannot be attributed to pre-existing page content.
pub fn rand_token(len: usize) -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// True when `signature` appears in the payload response but was **not**
/// already present in the baseline. This is what separates a real DB error
/// (triggered by our payload) from a page that always contains the word.
/// Comparison is case-insensitive; pass lowercased baseline text.
pub fn signature_is_new(baseline_lower: &str, response_lower: &str, signature: &str) -> bool {
    let sig = signature.to_lowercase();
    response_lower.contains(&sig) && !baseline_lower.contains(&sig)
}

/// True when `marker` appears verbatim (raw, unencoded) in the body. Used for
/// XSS: an HTML-entity-encoded reflection (`&lt;script&gt;`) will NOT contain
/// the raw `<script>` marker, so this only fires on genuinely unescaped output.
pub fn reflected_raw(body: &str, marker: &str) -> bool {
    body.contains(marker)
}

/// Similarity ratio in `[0.0, 1.0]` between two response bodies, based on
/// length and line-set overlap. 1.0 == effectively identical. Boolean-blind
/// detection uses this to require that a TRUE condition mirrors the baseline
/// while a FALSE condition clearly diverges — robust against pages whose byte
/// length wobbles slightly between requests.
pub fn body_similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let (la, lb) = (a.len() as f64, b.len() as f64);
    let len_ratio = la.min(lb) / la.max(lb);

    // Line-set Jaccard overlap captures structural (not just size) similarity.
    let sa: std::collections::HashSet<&str> = a.lines().collect();
    let sb: std::collections::HashSet<&str> = b.lines().collect();
    let inter = sa.intersection(&sb).count() as f64;
    let union = sa.union(&sb).count().max(1) as f64;
    let jaccard = inter / union;

    // Weighted blend: structure matters more than raw size.
    0.4 * len_ratio + 0.6 * jaccard
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rand_token_is_unique_and_sized() {
        let a = rand_token(12);
        let b = rand_token(12);
        assert_eq!(a.len(), 12);
        assert_ne!(a, b, "two tokens should not collide");
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn signature_new_only_when_absent_from_baseline() {
        // Error text already on the page → NOT attributable to our payload.
        assert!(!signature_is_new(
            "welcome, an error occurred earlier",
            "welcome, an error occurred earlier",
            "an error"
        ));
        // Error text appears only after injection → real signal.
        assert!(signature_is_new(
            "welcome home",
            "you have an error in your sql syntax near ''",
            "error in your sql syntax"
        ));
    }

    #[test]
    fn reflected_raw_rejects_encoded_reflection() {
        let marker = "<rzx>alert</rzx>";
        assert!(reflected_raw("<html><rzx>alert</rzx></html>", marker));
        // Entity-encoded output must NOT count as reflected.
        assert!(!reflected_raw(
            "<html>&lt;rzx&gt;alert&lt;/rzx&gt;</html>",
            marker
        ));
    }

    #[test]
    fn similarity_identical_and_divergent() {
        assert_eq!(body_similarity("same page", "same page"), 1.0);
        let a = "line1\nline2\nline3\nline4\nline5";
        let b = "line1\nline2\nline3\nline4\nline5";
        assert!(body_similarity(a, b) > 0.99);
        let c = "totally different content here";
        assert!(body_similarity(a, c) < 0.5);
    }

    #[test]
    fn similarity_handles_empty() {
        assert_eq!(body_similarity("", "x"), 0.0);
        assert_eq!(body_similarity("x", ""), 0.0);
    }
}
