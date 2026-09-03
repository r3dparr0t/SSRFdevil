// src/scanner/verdict.rs
//
// این فایل کارش قضاوته، نه اجرا و نه لاگ:
// - trace_engine: side-effect لحظه‌ای، تو لحظه‌ی send/receive صدا زده میشه (قبل/بعد هر request تکی)
// - scanner:      فقط مسئول فرستادنه، هیچی از "خوب بود یا بد" نمی‌دونه
// - verdict:      بعد از تموم شدن اسکن، رو کل Vec<ScanResult> یه پاس می‌زنه و طبقه‌بندی می‌کنه
//
// این نسخه با قابلیت evidence‑based indicators برای کاهش False Positive:
// - هر Rule می‌تونه success_indicator و failure_indicator داشته باشه (لیستی از literal:/regex:)
// - failure_indicator → رد قطعی (قبل از هر امتیازی)
// - success_indicator → +۳۰ امتیاز اضافه (فقط شواهد مثبت، نه شرط لازم)
// - اگر Rule متادیتا نداشته باشه، graceful ادامه میده (فقط امتیاز پایه)
// - کاملاً backward compatible با Ruleهای قدیمی (فیلدهای پیش‌فرض خالی)

use std::collections::HashMap;
use crate::{
    scanner::{scanner::ScanResult, indicator},
    engine::rule::RuleMeta,
};
use serde_json;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Confirmed,
    Likely,
    Suspicious,
    Rejected,
    Error,
}

pub struct VerdictSummary {
    pub confirmed: usize,
    pub likely: usize,
    pub suspicious: usize,
    pub rejected: usize,
    pub errors: usize,
}

pub struct VerdictResult {
    pub verdict: Verdict,
    pub score: u16,
    pub reasons: Vec<Reason>,
}

#[derive(Debug, Clone)]
pub enum Reason {
    Http2xx,
    Redirect,
    ClientError,
    ServerError,
    Timeout,
    Dns,
    ConnectionRefused,
    NegativeIndicator,      // از failure_indicator یا 4xx
    SuccessIndicator,       // از success_indicator - پیدا شد
    MissingSuccessIndicator, // رول success_indicator داشت ولی پیدا نشد -> سقف امتیاز
}

const SUCCESS_INDICATOR_BONUS: i32 = 30;

pub fn classify(scan: &ScanResult, rule_map: &HashMap<String, RuleMeta>) -> VerdictResult {
    let mut reasons = Vec::new();

    // ----------------------------
    // Transport errors
    // ----------------------------
    if let Some(err) = &scan.error {
        let err = err.to_ascii_lowercase();

        if err.contains("timeout") {
            reasons.push(Reason::Timeout);
        } else if err.contains("dns") {
            reasons.push(Reason::Dns);
        } else if err.contains("refused") {
            reasons.push(Reason::ConnectionRefused);
        }

        return VerdictResult {
            verdict: Verdict::Error,
            score: 0,
            reasons,
        };
    }

    // ----------------------------
    // HTTP response
    // ----------------------------
    let response = match &scan.response {
        Some(r) => r,
        None => {
            return VerdictResult {
                verdict: Verdict::Error,
                score: 0,
                reasons,
            };
        }
    };

    let body_text = String::from_utf8_lossy(&response.body);

    // ----------------------------
    // دریافت متادیتای Rule (graceful)
    // ----------------------------
    let rule_meta = rule_map.get(&scan.payload.rule_id);

    // ۱. بررسی failure_indicator (رد قطعی، اولویت بالا)
    if let Some(meta) = rule_meta {
        for pattern in &meta.failure_indicator {
            if indicator::matches(pattern, &body_text) {
                reasons.push(Reason::NegativeIndicator);
                return VerdictResult {
                    verdict: Verdict::Rejected,
                    score: 0,
                    reasons,
                };
            }
        }
    }

    // ۲. امتیاز status code (سیگنال غالب)
    let status_score: i32 = match response.status {
        200..=299 => {
            reasons.push(Reason::Http2xx);
            55
        }
        300..=399 => {
            reasons.push(Reason::Redirect);
            25
        }
        400..=499 => {
            reasons.push(Reason::ClientError);
            // 4xx → رد قطعی (حتی اگر failure_indicator وجود نداشته باشد)
            return VerdictResult {
                verdict: Verdict::Rejected,
                score: 0,
                reasons: vec![Reason::ClientError],
            };
        }
        500..=599 => {
            reasons.push(Reason::ServerError);
            15
        }
        _ => 0,
    };

    // ۳. امتیاز متادیتای Rule (severity + confidence) – مدیفایر محدود
    let metadata_score =
        calculate_metadata_score(scan.payload.severity.weight() as i32, scan.payload.confidence as i32);

    let mut score = (status_score + metadata_score).max(0);

    // ۴. بررسی success_indicator
    // نکته‌ی مهم: اگه رول اصلاً success_indicator تعریف نکرده باشه، رفتار قبلی
    // بدون تغییر می‌مونه (فقط status/متادیتا). ولی اگه رول صراحتاً success_indicator
    // تعریف کرده، یعنی ادعا می‌کنه می‌تونه content-aware باشه - در این حالت پیدا
    // نشدن اون نشونه دیگه فقط "بونوس رو از دست دادن" نیست، بلکه یعنی رول نتونسته
    // موفقیت واقعی رو تأیید کنه، پس نباید اجازه بده verdict به Confirmed/Likely برسه
    // (این دقیقاً همون چیزیه که false-positive endpoint نیاز داشت: status=200 خالی
    // از هر مدرکی نباید هم‌تراز با یه 200 با مدرک واقعی امتیاز بگیره).
    if let Some(meta) = rule_meta {
        if !meta.success_indicator.is_empty() {
            let matched_success = meta
                .success_indicator
                .iter()
                .any(|pattern| indicator::matches(pattern, &body_text));

            if matched_success {
                reasons.push(Reason::SuccessIndicator);
                score += SUCCESS_INDICATOR_BONUS;
            } else {
                reasons.push(Reason::MissingSuccessIndicator);
                // سقف سخت: پایین‌تر از آستانه‌ی Likely (50) نگه می‌داریم تا این
                // نتیجه حداکثر Suspicious بشه، نه Confirmed/Likely.
                score = score.min(49);
            }
        }
    }

    // ۵. Verdict نهایی
    let verdict = match score {
        70..=i32::MAX => Verdict::Confirmed,   // اصلاح: استفاده از i32::MAX
        50..=69 => Verdict::Likely,
        30..=49 => Verdict::Suspicious,
        _ => Verdict::Rejected,
    };

    VerdictResult {
        verdict,
        score: score as u16,
        reasons,
    }
}

fn calculate_metadata_score(severity_weight: i32, confidence: i32) -> i32 {
    severity_weight * 3 + confidence / 5
}

pub fn summarize(results: &[ScanResult], rule_map: &HashMap<String, RuleMeta>) -> VerdictSummary {
    let mut summary = VerdictSummary {
        confirmed: 0,
        likely: 0,
        suspicious: 0,
        rejected: 0,
        errors: 0,
    };

    for r in results {
        match classify(r, rule_map).verdict {
            Verdict::Confirmed => summary.confirmed += 1,
            Verdict::Likely => summary.likely += 1,
            Verdict::Suspicious => summary.suspicious += 1,
            Verdict::Rejected => summary.rejected += 1,
            Verdict::Error => summary.errors += 1,
        }
    }

    summary
}

struct ReportItem<'a> {
    scan: &'a ScanResult,
    verdict: VerdictResult,
}

pub fn print_report(results: &[ScanResult], rule_map: &HashMap<String, RuleMeta>) {
    println!("\n[+] ===== Scan Report =====");

    let mut report: Vec<ReportItem> = results
        .iter()
        .map(|scan| ReportItem {
            verdict: classify(scan, rule_map),
            scan,
        })
        .collect();

    report.sort_by(|a, b| b.verdict.score.cmp(&a.verdict.score));

    let interesting: Vec<&ReportItem> = report
        .iter()
        .filter(|item| matches!(item.verdict.verdict, Verdict::Confirmed | Verdict::Likely))
        .collect();

    if !interesting.is_empty() {
        println!("[!] {} finding(s), sorted by score:\n", interesting.len());
        for r in &interesting {
            let status = r.scan.response.as_ref().map(|resp| resp.status).unwrap_or(0);
            let tag = if r.verdict.verdict == Verdict::Confirmed {
                "🔥"
            } else {
                "⚠️"
            };
            println!(
                "  {} [{:>3}] sev={:<8} conf={:<3} rule={:<28} {} {} -> {}",
                tag,
                r.verdict.score,
                r.scan.payload.severity,
                r.scan.payload.confidence,
                r.scan.payload.rule_id,
                r.scan.payload.method,
                r.scan.payload.url,
                status
            );
        }
    } else {
        println!("[!] No confirmed or likely findings.");
    }

    use std::collections::{HashMap, HashSet};
    let mut rejected_by_rule: HashMap<&str, usize> = HashMap::new();
    let mut error_by_rule: HashMap<&str, usize> = HashMap::new();
    let mut suspicious_by_rule: HashMap<&str, usize> = HashMap::new();

    for item in &report {
        match item.verdict.verdict {
            Verdict::Rejected => *rejected_by_rule.entry(&item.scan.payload.rule_id).or_insert(0) += 1,
            Verdict::Error => *error_by_rule.entry(&item.scan.payload.rule_id).or_insert(0) += 1,
            Verdict::Suspicious => *suspicious_by_rule.entry(&item.scan.payload.rule_id).or_insert(0) += 1,
            _ => {}
        }
    }

    if !rejected_by_rule.is_empty() || !error_by_rule.is_empty() || !suspicious_by_rule.is_empty() {
        println!("\n[+] Filtered out (by rule):");
        let mut rule_ids: Vec<&str> = rejected_by_rule
            .keys()
            .chain(error_by_rule.keys())
            .chain(suspicious_by_rule.keys())
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        rule_ids.sort();
        for rule_id in rule_ids {
            let r = rejected_by_rule.get(rule_id).copied().unwrap_or(0);
            let e = error_by_rule.get(rule_id).copied().unwrap_or(0);
            let s = suspicious_by_rule.get(rule_id).copied().unwrap_or(0);
            let mut parts = Vec::new();
            if r > 0 {
                parts.push(format!("{} rejected", r));
            }
            if s > 0 {
                parts.push(format!("{} suspicious", s));
            }
            if e > 0 {
                parts.push(format!("{} error", e));
            }
            println!("  - {:<28} {}", rule_id, parts.join(", "));
        }
    }

    let summary = summarize(results, rule_map);
    println!(
        "\n[+] Total: {} | Confirmed: {} | Likely: {} | Suspicious: {} | Rejected: {} | Error: {}",
        results.len(),
        summary.confirmed,
        summary.likely,
        summary.suspicious,
        summary.rejected,
        summary.errors
    );
}

// ---- Export to JSON ----
pub fn export_json(results: &[ScanResult], rule_map: &HashMap<String, RuleMeta>) -> String {
    let mut findings = Vec::new();

    for scan in results {
        let verdict = classify(scan, rule_map);
        let status = scan.response.as_ref().map(|resp| resp.status).unwrap_or(0);
        let error = scan.error.clone().unwrap_or_else(|| "".to_string());

        let item = serde_json::json!({
            "rule_id": scan.payload.rule_id,
            "method": scan.payload.method,
            "url": scan.payload.url,
            "status": status,
            "score": verdict.score,
            "verdict": format!("{:?}", verdict.verdict),
            "reasons": format!("{:?}", verdict.reasons),
            "severity": format!("{:?}", scan.payload.severity),
            "confidence": scan.payload.confidence,
            "error": error,
        });
        findings.push(item);
    }

    let summary = summarize(results, rule_map);

    let output = serde_json::json!({
        "summary": {
            "total": results.len(),
            "confirmed": summary.confirmed,
            "likely": summary.likely,
            "suspicious": summary.suspicious,
            "rejected": summary.rejected,
            "errors": summary.errors,
        },
        "findings": findings,
    });
    serde_json::to_string_pretty(&output).unwrap()
}

// ---- Export to Markdown ----
pub fn export_markdown(results: &[ScanResult], rule_map: &HashMap<String, RuleMeta>) -> String {
    let mut md = String::new();
    md.push_str("# SSRFdevil Scan Report\n\n");

    let summary = summarize(results, rule_map);
    md.push_str("## Summary\n\n");
    md.push_str("| Metric | Count |\n|--------|-------|\n");
    md.push_str(&format!("| Total | {} |\n", results.len()));
    md.push_str(&format!("| Confirmed | {} |\n", summary.confirmed));
    md.push_str(&format!("| Likely | {} |\n", summary.likely));
    md.push_str(&format!("| Suspicious | {} |\n", summary.suspicious));
    md.push_str(&format!("| Rejected | {} |\n", summary.rejected));
    md.push_str(&format!("| Errors | {} |\n", summary.errors));
    md.push_str("\n");

    // Findings
    let mut report: Vec<ReportItem> = results
        .iter()
        .map(|scan| ReportItem {
            verdict: classify(scan, rule_map),
            scan,
        })
        .collect();

    report.sort_by(|a, b| b.verdict.score.cmp(&a.verdict.score));

    let interesting: Vec<&ReportItem> = report
        .iter()
        .filter(|item| matches!(item.verdict.verdict, Verdict::Confirmed | Verdict::Likely))
        .collect();

    if !interesting.is_empty() {
        md.push_str("## Findings\n\n");
        md.push_str("| # | Score | Severity | Confidence | Rule | Method | URL | Status |\n");
        md.push_str("|---|-------|----------|------------|------|--------|-----|--------|\n");
        for (i, r) in interesting.iter().enumerate() {
            let status = r.scan.response.as_ref().map(|resp| resp.status).unwrap_or(0);
            md.push_str(&format!(
                "| {} | {} | {:?} | {} | {} | {} | {} | {} |\n",
                i + 1,
                r.verdict.score,
                r.scan.payload.severity,
                r.scan.payload.confidence,
                r.scan.payload.rule_id,
                r.scan.payload.method,
                r.scan.payload.url,
                status
            ));
        }
        md.push_str("\n");
    } else {
        md.push_str("## Findings\n\nNo confirmed or likely findings.\n\n");
    }

    // Filtered out
    use std::collections::{HashMap, HashSet};
    let mut rejected_by_rule: HashMap<&str, usize> = HashMap::new();
    let mut error_by_rule: HashMap<&str, usize> = HashMap::new();
    let mut suspicious_by_rule: HashMap<&str, usize> = HashMap::new();

    for item in &report {
        match item.verdict.verdict {
            Verdict::Rejected => *rejected_by_rule.entry(&item.scan.payload.rule_id).or_insert(0) += 1,
            Verdict::Error => *error_by_rule.entry(&item.scan.payload.rule_id).or_insert(0) += 1,
            Verdict::Suspicious => *suspicious_by_rule.entry(&item.scan.payload.rule_id).or_insert(0) += 1,
            _ => {}
        }
    }

    if !rejected_by_rule.is_empty() || !error_by_rule.is_empty() || !suspicious_by_rule.is_empty() {
        md.push_str("## Filtered Out (by rule)\n\n");
        let mut rule_ids: Vec<&str> = rejected_by_rule
            .keys()
            .chain(error_by_rule.keys())
            .chain(suspicious_by_rule.keys())
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect();
        rule_ids.sort();

        md.push_str("| Rule | Rejected | Suspicious | Errors |\n");
        md.push_str("|------|----------|------------|--------|\n");
        for rule_id in rule_ids {
            let r = rejected_by_rule.get(rule_id).copied().unwrap_or(0);
            let s = suspicious_by_rule.get(rule_id).copied().unwrap_or(0);
            let e = error_by_rule.get(rule_id).copied().unwrap_or(0);
            md.push_str(&format!("| {} | {} | {} | {} |\n", rule_id, r, s, e));
        }
        md.push_str("\n");
    }

    md
}
