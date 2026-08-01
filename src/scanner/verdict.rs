// src/scanner/verdict.rs
//
// این فایل کارش قضاوته، نه اجرا و نه لاگ:
// - trace_engine: side-effect لحظه‌ای، تو لحظه‌ی send/receive صدا زده میشه (قبل/بعد هر request تکی)
// - scanner:      فقط مسئول فرستادنه، هیچی از "خوب بود یا بد" نمی‌دونه
// - verdict:      بعد از تموم شدن اسکن، رو کل Vec<ScanResult> یه پاس می‌زنه و طبقه‌بندی می‌کنه
//
// نکته‌ی مهم: تو rule.rs فعلا هیچ فیلدی برای "این پاسخ یعنی موفق" وجود نداره
// (نه expected_status، نه body/header indicator regex) - فقط MatchConfig هست که
// قبل از اجرا تارگت‌ها رو فیلتر می‌کنه، نه بعد از اجرا جواب رو تفسیر کنه.
// پس تنها سیگنال واقعی برای Ok/Failed همچنان status codeست. کاری که اینجا اضافه
// شده اینه که با meta.severity و meta.confidence رول، نتیجه رو اولویت‌بندی می‌کنیم:
// یه 200 از یه رول severity=critical/confidence بالا خیلی مهم‌تر از یه 200
// از یه رول کم‌اهمیته. اگه بعدا خواستی قضاوت واقعا content-aware بشه
// (مثلا body باید فلان رجکس رو داشته باشه) باید یه بلاک `detect` به RuleFile/YAML
// اضافه کنیم - الان اون زیرساخت وجود نداره.

use crate::scanner::scanner::ScanResult;

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
}

pub fn classify(scan: &ScanResult) -> VerdictResult {
    let mut score: u16 = 0;
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

    match response.status {
        200..=299 => {
            score += 40;
            reasons.push(Reason::Http2xx);
        }

        300..=399 => {
            score += 15;
            reasons.push(Reason::Redirect);
        }

        400..=499 => {
            reasons.push(Reason::ClientError);
        }

        500..=599 => {
            score += 10;
            reasons.push(Reason::ServerError);
        }

        _ => {}
    }

    // ----------------------------
    // Rule metadata
    // ----------------------------
    score += calculate_metadata_score(scan.payload.severity.weight() as u16 , scan.payload.confidence as u16);

    // ----------------------------
    // Final verdict
    // ----------------------------

    let verdict = match score {
        90..=u16::MAX => Verdict::Confirmed,
        70..=89 => Verdict::Likely,
        40..=69 => Verdict::Suspicious,
        _ => Verdict::Rejected,
    };

    VerdictResult {
        verdict,
        score,
        reasons,
    }
}

pub fn summarize(results: &[ScanResult]) -> VerdictSummary {

    let mut summary = VerdictSummary {
        confirmed: 0,
        likely: 0,
        suspicious: 0,
        rejected: 0,
        errors: 0,
    };

    for r in results {

        match classify(r).verdict {

            Verdict::Confirmed =>
                summary.confirmed += 1,

            Verdict::Likely =>
                summary.likely += 1,

            Verdict::Suspicious =>
                summary.suspicious += 1,

            Verdict::Rejected =>
                summary.rejected += 1,

            Verdict::Error =>
                summary.errors += 1,
        }
    }

    summary
}

fn calculate_metadata_score(
    severity_weight: u16,
    confidence: u16
) -> u16 {
    severity_weight * 10 + confidence
}

struct ReportItem<'a> {
    scan: &'a ScanResult,
    verdict: VerdictResult,
}

/// این رو مستقیم از کنسول صدا بزن، بعد از scanner.run_full_scan(...)
/// Ok‌ها بر اساس (severity, confidence) نزولی مرتب میشن میان بالای گزارش،
/// چون این‌ها همونایی هستن که اول باید دستی بررسیشون کنی.
pub fn print_report(results: &[ScanResult]) {
    println!("\n[+] ===== Scan Report =====");
    let report: Vec<ReportItem> = results
    .iter()
    .map(|scan| ReportItem {
        verdict: classify(scan),
        scan,
    })
    .collect();
    
    let interesting: Vec<&ReportItem> = report
    .iter()
    .filter(|item| {
        matches!(
            item.verdict.verdict,
            Verdict::Confirmed | Verdict::Likely
        )
    })
    .collect();

    if !interesting.is_empty() {
        println!("[!] Sorted by majority.");
        for r in &interesting {
            let status = r.scan.response.as_ref().map(|resp| resp.status).unwrap_or(0);
            println!(
                "  [✅ OK] severity={} confidence={} rule={} {} {} -> {}",
                r.scan.payload.severity, r.scan.payload.confidence, r.scan.payload.rule_id,
                r.scan.payload.method, r.scan.payload.url, status
            );
        }
    }

    let others: Vec<&ReportItem> = report
        .iter()
        .filter(|item| {
            !matches!(
                item.verdict.verdict,
                Verdict::Confirmed | Verdict::Likely
            )
        })
        .collect();
    if !others.is_empty() {
        println!("[+] The rest:");
        for r in others {
            let tag = match r.verdict.verdict {
                Verdict::Suspicious => "⚠️ Suspicious",
                Verdict::Rejected => "❌ Rejected",
                Verdict::Error => "💀 Error",
                Verdict::Confirmed => "🔥 Confirmed",
                Verdict::Likely => "⚠️ Likely",
            };
                let status_str = r.scan.response.as_ref()
                .map(|resp| resp.status.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "  [{}] rule={} {} {} -> {}",
                tag, r.scan.payload.rule_id, r.scan.payload.method, r.scan.payload.url, status_str
            );
        }
    }

    let summary = summarize(results);
    println!(
        "[+] Total: {} | Confirmed: {} | Likely: {} | Suspicious: {} | Rejected: {} | Error: {}",
        results.len(),
        summary.confirmed,
        summary.likely,
        summary.suspicious,
        summary.rejected,
        summary.errors
    );
}
