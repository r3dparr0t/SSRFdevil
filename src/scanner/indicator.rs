// src/scanner/indicator.rs

/// تطابق یک الگو با متن داده شده.
/// فرمت‌های پشتیبانی‌شده:
/// - "literal:ACCESS DENIED" → تطابق case‑insensitive
/// - "regex:blocked|denied" → تطابق با regex (case‑insensitive)
/// - بدون پیشوند → literal case‑insensitive (سازگاری با قدیم)
pub fn matches(pattern: &str, text: &str) -> bool {
    if let Some(stripped) = pattern.strip_prefix("literal:") {
        text.to_ascii_lowercase()
            .contains(&stripped.to_ascii_lowercase())
    } else if let Some(stripped) = pattern.strip_prefix("regex:") {
        regex::RegexBuilder::new(stripped)
            .case_insensitive(true)
            .build()
            .map(|re| re.is_match(text))
            .unwrap_or(false) // اگر regex نامعتبر باشد، نادیده می‌گیریم
    } else {
        // بدون پیشوند → literal case‑insensitive
        text.to_ascii_lowercase()
            .contains(&pattern.to_ascii_lowercase())
    }
}
