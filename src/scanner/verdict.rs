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
    Ok,      // status تو رنج 2xx برگشت
    Failed,  // request جواب داد ولی status غیرمنتظره بود (3xx/4xx/5xx)
    Errored, // اصلاً request رد نشد (timeout, DNS, connection refused, payload نامعتبر, ...)
}

pub fn classify(result: &ScanResult) -> Verdict {
    if result.error.is_some() {
        return Verdict::Errored;
    }
    match &result.response {
        Some(resp) if (200..300).contains(&resp.status) => Verdict::Ok,
        Some(_) => Verdict::Failed,
        None => Verdict::Errored,
    }
}

/// اولویت عددی severity برای مرتب‌سازی. مقادیر ناشناخته (typo تو YAML مثلا) میرن ته لیست
/// به‌جای اینکه کرش کنن یا رد بشن.
fn severity_weight(sev: &str) -> u8 {
    match sev.to_ascii_lowercase().as_str() {
        "critical" => 4,
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        "info" | "informational" => 0,
        _ => 0,
    }
}

pub fn summarize(results: &[ScanResult]) -> (usize, usize, usize) {
    let mut ok = 0;
    let mut failed = 0;
    let mut errored = 0;
    for r in results {
        match classify(r) {
            Verdict::Ok => ok += 1,
            Verdict::Failed => failed += 1,
            Verdict::Errored => errored += 1,
        }
    }
    (ok, failed, errored)
}

/// این رو مستقیم از کنسول صدا بزن، بعد از scanner.run_full_scan(...)
/// Ok‌ها بر اساس (severity, confidence) نزولی مرتب میشن میان بالای گزارش،
/// چون این‌ها همونایی هستن که اول باید دستی بررسیشون کنی.
pub fn print_report(results: &[ScanResult]) {
    println!("\n[+] ===== Scan Report =====");

    let mut ok_results: Vec<&ScanResult> = results.iter()
        .filter(|r| classify(r) == Verdict::Ok)
        .collect();
    ok_results.sort_by(|a, b| {
        let a_w = (severity_weight(&a.payload.severity), a.payload.confidence);
        let b_w = (severity_weight(&b.payload.severity), b.payload.confidence);
        b_w.cmp(&a_w)
    });

    if !ok_results.is_empty() {
        println!("  -- احتمالی (Ok, به ترتیب اهمیت) --");
        for r in &ok_results {
            let status = r.response.as_ref().map(|resp| resp.status).unwrap_or(0);
            println!(
                "  [✅ OK] severity={} confidence={} rule={} {} {} -> {}",
                r.payload.severity, r.payload.confidence, r.payload.rule_id,
                r.payload.method, r.payload.url, status
            );
        }
    }

    let others: Vec<&ScanResult> = results.iter()
        .filter(|r| classify(r) != Verdict::Ok)
        .collect();
    if !others.is_empty() {
        println!("  -- بقیه --");
        for r in others {
            let v = classify(r);
            let tag = match v {
                Verdict::Ok => unreachable!(),
                Verdict::Failed => "⚠️  FAIL",
                Verdict::Errored => "❌ ERR",
            };
            let status_str = r.response.as_ref()
                .map(|resp| resp.status.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "  [{}] rule={} {} {} -> {}",
                tag, r.payload.rule_id, r.payload.method, r.payload.url, status_str
            );
        }
    }

    let (ok, failed, errored) = summarize(results);
    println!(
        "[+] Total: {} | OK: {} | Failed: {} | Errored: {}",
        results.len(), ok, failed, errored
    );
    println!("[+] =========================\n");
}
