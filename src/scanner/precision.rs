// ----------------------------------------------------------------------------
//  precision.rs — CGI precision validator
// ----------------------------------------------------------------------------
//  Eliminates false positives from CGI scan results by applying multi-layer
//  evidence checks: HTTP status matching, content indicator verification,
//  generic error/WAF page detection, body length floor, and weak indicator
//  filtering. Only confirms findings that pass all validation layers.
//
//  --- Developers ---------------------------------------------------------------
//  khaninkali             — разработчик / core engineer (Rust backend, logic)
//  Lyara Koroleva         — дизайнер / blazing fast CLI & interface design
//  HsecDevelopers         — 测试 / テスト / testing & QA (integration, validation)
//  projectk 2091         — HyperSecurityOffensiveLabs lineage
// ----------------------------------------------------------------------------

//
//
// ---------------------------------------------------------------------------
//   WARNING / 警告 / 警告
// ---------------------------------------------------------------------------
//  This source code is the exclusive property of HyperSecurityOffensiveLabs.
//  You are permitted to VIEW this code for educational and reference
//  purposes only. You may NOT modify, distribute, sublicense, or create
//  derivative works without explicit written permission from khaninkali
//  and the HyperSecurityOffensiveLabs development team.
//
//  このソースコードはHyperSecurityOffensiveLabsの独占的知的財産です
//  教育目的および参照目的での閲覧のみ許可されています
//  khaninkaliおよびHyperSecurityOffensiveLabs開発チームの
//  書面による明示的な許可なく修正配布サブライセンス
//  または二次的著作物の作成を禁止します
//
//  本源代码是HyperSecurityOffensiveLabs的独家财产
//  仅允许出于教育和参考目的查看未经khaninkali和
//  HyperSecurityOffensiveLabs开发团队的书面明确许可，
//  禁止修改分发再许可或创建衍生作品
// ---------------------------------------------------------------------------
//
//

//  CGI精度検証 / CGI precision validation — false positive elimination engine:
//   ① HTTP status matching: expects specific status codes per CGI path
//   ② Content indicator verification: requires structural evidence in body
//   ③ Generic error/WAF detection: 22 patterns (404/403/CDN/error pages)
//   ④ Body length floor: responses < 64 bytes are error stubs, rejected
//   ⑤ Weak indicator filtering: "200", "ok", "true", "false" — not evidence
//   ⑥ Confidence scoring: match ratio + high-value bonus (root:x  0.35,
//      phpinfo  0.25, phpMyAdmin  0.2) - size penalty for CDN cache dumps
//    Rejection cascade: if ANY layer fails, return Rejected with reason.
//     Confirmed only when ALL layers pass and confidence  0.5 baseline.
//     Non-200 status (401/403/500) on specific CGI paths = real finding even
//     without strong indicators (confidence 0.3).
//! CGI Precision Validator
//! Eliminates false positives from CGI scan results by applying
//! multi-layer evidence checks before a finding is accepted.
//!
//! A result is only confirmed when ALL of the following hold:
//!   1. HTTP status matches the expected set
//!   2. At least one content indicator is present in the body
//!   3. The response is not a generic error page (404/WAF/CDN)
//!   4. The body length is above the noise floor
//!   5. The content indicator is not trivially present on every page

use std::collections::HashSet;

/// Minimum body length (bytes) before we trust content indicators.
/// Responses shorter than this are almost always error stubs.
const MIN_BODY_LEN: usize = 64;

/// Strings that appear on generic error / WAF / CDN pages.
/// If the body contains one of these AND no real indicator, it's a false positive.
const GENERIC_ERROR_PATTERNS: &[&str] = &[
    "404 not found",
    "403 forbidden",
    "access denied",
    "page not found",
    "the page you requested",
    "cloudflare",
    "incapsula",
    "sucuri",
    "akamai ghost",
    "request blocked",
    "this site can't be reached",
    "nginx 404",
    "apache 404",
    "iis 404",
    "object not found",
    "no such file",
    "document not found",
    "error 404",
    "error 403",
    "you don't have permission",
    "default web site page",
    "it works!",          // bare Apache default — not a finding
    "welcome to nginx",   // bare Nginx default
];

/// Indicators that are so common they appear on almost every page.
/// Matching only these without a stronger signal is not enough.
const WEAK_INDICATORS: &[&str] = &[
    "",       // empty indicator — always matches, meaningless
    "200",
    "ok",
    "true",
    "false",
    "null",
    "{}",
    "[]",
];

/// Result of a precision check.
#[derive(Debug, Clone, PartialEq)]
pub enum PrecisionVerdict {
    /// Confirmed finding — evidence is solid.
    Confirmed {
        matched_indicators: Vec<String>,
        confidence: f64,
    },
    /// Rejected — likely a false positive.
    Rejected {
        reason: String,
    },
}

impl PrecisionVerdict {
    pub fn is_confirmed(&self) -> bool {
        matches!(self, PrecisionVerdict::Confirmed { .. })
    }

    pub fn confidence(&self) -> f64 {
        match self {
            PrecisionVerdict::Confirmed { confidence, .. } => *confidence,
            PrecisionVerdict::Rejected { .. } => 0.0,
        }
    }
}

/// Validate a CGI scan result before accepting it as a real finding.
///
/// # Arguments
/// * `status`      — HTTP status code returned
/// * `body`        — Response body text
/// * `expected_status` — Status codes that indicate a hit
/// * `indicators`  — Content strings that must appear in the body
/// * `path`        — The CGI path tested (used for context scoring)
pub fn validate(
    status: u16,
    body: &str,
    expected_status: &[u16],
    indicators: &[String],
    _path: &str,
) -> PrecisionVerdict {
    //  1. Status check 
    if !expected_status.contains(&status) {
        return PrecisionVerdict::Rejected {
            reason: format!("status {} not in expected {:?}", status, expected_status),
        };
    }

    //  2. Body length floor 
    if body.len() < MIN_BODY_LEN {
        return PrecisionVerdict::Rejected {
            reason: format!("body too short ({} bytes)", body.len()),
        };
    }

    let body_lower = body.to_lowercase();

    //  3. Generic error / WAF page detection 
    // If the body looks like a generic error page, reject unless a strong
    // indicator is also present.
    let is_generic_error = GENERIC_ERROR_PATTERNS
        .iter()
        .any(|p| body_lower.contains(p));

    //  4. Content indicator matching 
    // Filter out weak/empty indicators first.
    let weak_set: HashSet<&str> = WEAK_INDICATORS.iter().copied().collect();
    let strong_indicators: Vec<&String> = indicators
        .iter()
        .filter(|i| !weak_set.contains(i.to_lowercase().as_str()))
        .collect();

    // If all indicators are weak, we NEVER confirm based on status alone.
    // A 200 OK from a catch-all router (e.g. qoo10.jp) is NOT evidence that
    // a CGI script exists. Only non-200 codes (401, 403, 500) on specific
    // paths are meaningful.
    if strong_indicators.is_empty() {
        if status == 200 || status == 404 {
            return PrecisionVerdict::Rejected {
                reason: "no strong content indicators — status alone is not evidence".to_string(),
            };
        }
        // Non-200 specific status (401, 403 on admin/CGI paths is real)
        return PrecisionVerdict::Confirmed {
            matched_indicators: vec![format!("HTTP {}", status)],
            confidence: 0.3,
        };
    }

    // Match strong indicators against body
    let matched: Vec<String> = strong_indicators
        .iter()
        .filter(|ind| body_lower.contains(ind.to_lowercase().as_str()))
        .map(|ind| ind.to_string())
        .collect();

    if matched.is_empty() {
        return PrecisionVerdict::Rejected {
            reason: "no content indicators matched in response body".to_string(),
        };
    }

    //  5. Generic error + indicator conflict 
    // If the page looks like a generic error AND the matched indicator is
    // something trivially present (e.g. "error" on an error page), reject.
    if is_generic_error {
        let non_trivial: Vec<&String> = matched
            .iter()
            .filter(|m| {
                let ml = m.to_lowercase();
                // These words appear on error pages themselves
                !matches!(ml.as_str(), "error" | "warning" | "not found" | "forbidden")
            })
            .collect();

        if non_trivial.is_empty() {
            return PrecisionVerdict::Rejected {
                reason: "matched indicators are trivially present on error pages".to_string(),
            };
        }
    }

    //  6. Confidence scoring 
    let match_ratio = if strong_indicators.is_empty() {
        0.0
    } else {
        matched.len() as f64 / strong_indicators.len() as f64
    };

    // Boost confidence for high-value indicators
    // Each check requires structural context — bare words like "passwd" or "sql" do not trigger
    let high_value_bonus: f64 = matched.iter().map(|m| {
        let ml = m.to_lowercase();
        if ml.contains("root:x:0:0") { 0.35 }
        else if ml.contains("phpinfo()") || ml.contains("php version ") { 0.25 }
        else if ml.contains("phpmyadmin") || ml.contains("adminer") { 0.2 }
        else if ml.contains("sql syntax") || ml.contains("mysql_error") { 0.15 }
        else if ml.contains("server_software") || ml.contains("document_root") { 0.2 }
        else { 0.0 }
    }).sum::<f64>().min(0.4);

    // Penalise if body is suspiciously large (CDN cache dump)
    let size_penalty = if body.len() > 500_000 { 0.15 } else { 0.0 };

    let confidence = (0.5 + match_ratio * 0.3 + high_value_bonus - size_penalty).clamp(0.0, 1.0);

    PrecisionVerdict::Confirmed {
        matched_indicators: matched,
        confidence,
    }
}

/// One-line CGI progress bar — no emoji, bidirectional braille spinner.
/// Returns a `\r`-prefixed string — caller prints it to overwrite the line.
///
/// Example:
/// ` CGI [========--------] 1240/2790 (44%) [+3] /cgi-bin/test.cgi`
pub fn cgi_progress_line(
    current: usize,
    total: usize,
    hits: usize,
    current_path: &str,
    spinner_frame: &str,
) -> String {
    let pct      = if total > 0 { ((current * 100) / total).min(100) } else { 0 };
    let bar_width = 16usize;
    let filled   = ((pct * bar_width) / 100).min(bar_width);
    let empty    = bar_width.saturating_sub(filled);

    // ASCII fill — no emoji, works on all terminals
    let bar = format!(
        "\x1B[92m{}\x1B[90m{}\x1B[0m",
        "=".repeat(filled),
        "-".repeat(empty),
    );

    // Truncate path — plain ASCII ellipsis
    let path_display = if current_path.len() > 42 {
        format!("...{}", &current_path[current_path.len().saturating_sub(39)..])
    } else {
        current_path.to_string()
    };

    // hits marker: plain ASCII [+N]
    let hits_str = if hits > 0 {
        format!("\x1B[92m[+{}]\x1B[0m", hits)
    } else {
        "\x1B[90m[+0]\x1B[0m".to_string()
    };

    format!(
        "\r\x1B[96m{}\x1B[0m CGI [{}] \x1B[97m{}/{}\x1B[0m \x1B[90m({}%)\x1B[0m {} \x1B[90m{}\x1B[0m",
        spinner_frame, bar, current, total, pct, hits_str, path_display
    )
}

/// Bidirectional braille spinner — alternates CW then CCW so the animation
/// visually bounces. Pass the current iteration index.
pub fn bidir_braille(idx: usize) -> &'static str {
    const FRAMES: &[&str] = &[
        "⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏",  // clockwise
        "⠏","⠇","⠧","⠦","⠴","⠼","⠸","⠹","⠙","⠋",  // counter-clockwise
    ];
    FRAMES[idx % FRAMES.len()]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_body() {
        let v = validate(200, "short", &[200], &["/etc/passwd".to_string()], "/cgi-bin/test");
        assert!(!v.is_confirmed());
    }

    #[test]
    fn rejects_generic_404_page() {
        let body = "a".repeat(200) + "404 not found - the page you requested was not found";
        let v = validate(200, &body, &[200], &["error".to_string()], "/cgi-bin/test");
        assert!(!v.is_confirmed());
    }

    #[test]
    fn confirms_real_passwd_leak() {
        let body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";
        let v = validate(200, body, &[200], &["root:x".to_string()], "/cgi-bin/test");
        assert!(v.is_confirmed());
        assert!(v.confidence() > 0.7);
    }

    #[test]
    fn confirms_phpinfo() {
        let body = "PHP Version 8.1.0 phpinfo() PHP Credits</title>\n\
                     This is a phpinfo page with configuration details loaded from the server environment settings and compiled PHP modules";
        let v = validate(200, body, &[200], &["phpinfo".to_string(), "PHP Version".to_string()], "/cgi-bin/php");
        assert!(v.is_confirmed());
    }

    #[test]
    fn rejects_weak_indicator_on_normal_page() {
        let body = "Welcome to our website. Everything is fine here. Have a great day!";
        let v = validate(200, &body, &[200], &["".to_string()], "/random/path");
        assert!(!v.is_confirmed());
    }
}
