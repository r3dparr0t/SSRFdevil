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
//
// نسخه‌ی قبلی این فایل یه باگ اساسی داشت: severity_weight*10 + confidence می‌تونست
// به‌تنهایی (بدون توجه به این‌که پاسخ چی بوده) از آستانه‌ی Confirmed رد بشه. یعنی
// یه رول severity=high/confidence=90 حتی وقتی سرور با 403 "Access Denied" جواب
// می‌داد Confirmed می‌شد، چون هیچ status codeای امتیاز رو صفر یا منفی نمی‌کرد.
//
// اصلاح‌شده: حالا status code سیگنال غالبه، نه متادیتا:
//   - 2xx / 3xx / 5xx: امتیاز پایه می‌گیرن و متادیتای رول روش سوار میشه (مدیفایر محدود)
//   - 4xx: floor سخت داره -> همیشه Rejected، صرف‌نظر از severity/confidence رول،
//     چون تو عمل یعنی اپلیکیشن قبل از هر اتفاقی درخواست رو رد کرده
// علاوه بر این، یه چک عمومی و مستقل از rule-schema روی متن پاسخ اضافه شده: اگه
// body حاوی عبارات رایج رد شدن باشه (denied/forbidden/blocked/...)، صرف‌نظر از
// status، verdict به Rejected افت می‌کنه. این چک به هیچ فیلدی تو RuleFile/YAML
// نیاز نداره - کاملاً جدا از تعریف رول‌هاست.
//
// چیزی که این فایل هنوز حل نمی‌کنه: false positive مثل اندپوینت آزمایشی که بدون
// زدن هیچ درخواستی، متن "Internal Admin Interface" رو با status 200 برمی‌گردونه.
// تشخیص واقعی این مورد نیاز به یه لایه‌ی content-aware اختصاصی به هر رول داره
// (یه بلاک detect جدا از match/script) که فعلا خارج از scope همین فیکسه.

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
    // سیگنال عمومی و مستقل از رول: body حاوی عبارت رایج رد شدنه.
    NegativeIndicator,
}

// عبارات عمومی و رایج رد شدن که اکثر اپلیکیشن‌ها موقع بلاک کردن یه درخواست
// برمی‌گردونن. عمداً generic نگه داشته شده (نه رجکس رول-اسپسیفیک)، چون این
// چک باید مستقل از تعریف تک‌تک رول‌ها باشه.
const REJECTION_KEYWORDS: &[&str] = &[
    "access denied",
    "forbidden",
    "blocked",
    "unauthorized",
    "permission denied",
    "not allowed",
];

pub fn classify(scan: &ScanResult) -> VerdictResult {
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

    // چک عمومی روی متن پاسخ - قبل از هر محاسبه‌ی امتیاز، چون این سیگنال
    // باید بتونه صرف‌نظر از status code یا متادیتای رول، verdict رو رد کنه.
    let body_text = String::from_utf8_lossy(&response.body).to_ascii_lowercase();
    let has_rejection_text = REJECTION_KEYWORDS.iter().any(|kw| body_text.contains(kw));
    if has_rejection_text {
        reasons.push(Reason::NegativeIndicator);
    }

    // status code به‌عنوان سیگنال غالب. توجه: 4xx یه floor سخته، نه فقط
    // "امتیاز نگرفتن" - چون تو عمل یعنی اپلیکیشن قبل از انجام کاری درخواست
    // رو رد کرده، پس هیچ متادیتای رولی نباید بتونه این رو دور بزنه.
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
            i32::MIN // floor سخت؛ پایین‌تر پردازش می‌شه
        }
        500..=599 => {
            reasons.push(Reason::ServerError);
            15
        }
        _ => 0,
    };

    // اگه رد شدن قطعیه (چه از طریق 4xx، چه از طریق متن body)، همینجا با
    // Rejected برگرد؛ متادیتای رول اجازه نداره این تصمیم رو دور بزنه.
    if status_score == i32::MIN || has_rejection_text {
        return VerdictResult {
            verdict: Verdict::Rejected,
            score: 0,
            reasons,
        };
    }

    // ----------------------------
    // Rule metadata - فقط یه مدیفایر محدوده، نه یه مسیر مستقل به Confirmed.
    // بیشترین مقداری که می‌تونه بده: severity critical(4)*3 + confidence 100/5
    // = 12 + 20 = 32، که به‌تنهایی حتی با بالاترین status_score (55) هم به
    // ۹۰ (آستانه‌ی Confirmed) نمی‌رسه مگر این‌که واقعا 2xx باشه.
    // ----------------------------
    let metadata_score =
        calculate_metadata_score(scan.payload.severity.weight() as i32, scan.payload.confidence as i32);

    let score = (status_score + metadata_score).max(0) as u16;

    // ----------------------------
    // Final verdict
    // ----------------------------
    let verdict = match score {
        70..=u16::MAX => Verdict::Confirmed,
        50..=69 => Verdict::Likely,
        30..=49 => Verdict::Suspicious,
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

// مدیفایر محدود: severity_weight*3 (0..=12) + confidence/5 (0..=20) => جمعاً
// حداکثر 32. این عمداً کوچیکه تا هیچ ترکیبی از severity/confidence نتونه
// به‌تنهایی status_score رو دور بزنه یا از 4xx floor عبور کنه.
fn calculate_metadata_score(
    severity_weight: i32,
    confidence: i32
) -> i32 {
    severity_weight * 3 + confidence / 5
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
