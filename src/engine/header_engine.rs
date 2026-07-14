// engine/header_engine.rs
use reqwest::header::{
    HeaderMap,
    HeaderName,
    HeaderValue
};
use std::{
    collections::HashMap,
    sync::{LazyLock, RwLock}
};

// استفاده از LazyLock برای مقداردهی اولیه در static
static CUSTOM_HEADERS: LazyLock<RwLock<HashMap<String, String>>> =
    LazyLock::new(|| RwLock::new(HashMap::new()));

// پروفایل بومی کروم - هر هدر پیش‌فرض یک ردیف اینجا. اضافه/حذف کردن هدر پیش‌فرض
// فقط با دستکاری همین آرایه انجام می‌شود، نه insert جداگانه.
const DEFAULT_HEADERS: &[(&str, &str)] = &[
	("Accept", "text/html,application/xhtml+xml,image/avif,image/webp,*/*;q=0.8"),
	("Accept-Language", "en-US,en;q=0.5"),
	("Sec-Fetch-Dest", "document"),
	// هدرهای امنیتی مدرن مرورگرها برای دور زدن مکانیزم‌های تشخیص بات
	("Sec-Fetch-Mode", "navigate"),
	("Sec-Fetch-Site", "none"),
	("Sec-Fetch-User", "?1"),
	("Upgrade-Insecure-Requests", "1"),
	("Accept-Encoding", "gzip, deflate, br"),
	("Connection", "keep-alive"),
	("Cache-Control", "max-age=0"),
];

pub fn inject(headers: &mut HeaderMap) {
	inject_defaults(headers);
	// هدرهای اختیاری کاربر (تشخیص کاملاً دستی خودش) - همیشه بعد از پیش‌فرض‌ها،
	// چون اگر کلیدی تکراری باشد پیش‌فرض حفظ می‌شود و کاستوم آن را overwrite نمی‌کند.
	inject_custom_headers(headers);
}

fn inject_defaults(headers: &mut HeaderMap) {
	for (k, v) in DEFAULT_HEADERS {
		headers.insert(*k, HeaderValue::from_static(v));
	}
}

/// یک هدر اختیاری تک را به تنظیمات سراسری اضافه می‌کند.
/// کنسول این تابع را برای هر خط ورودی کاربر صدا می‌زند؛ اعتبارسنجی همینجا
/// انجام می‌شود تا خطای فرمت فوراً به کاربر نمایش داده شود، نه موقع ارسال ریکوئست.
pub fn add_custom_header(key: &str, value: &str) -> Result<(), String> {
	// فقط برای اعتبارسنجی زودهنگام؛ مقدار نهایی موقع inject دوباره پارس می‌شود.
	HeaderName::try_from(key).map_err(|e| e.to_string())?;
	HeaderValue::try_from(value).map_err(|e| e.to_string())?;

	CUSTOM_HEADERS.write().unwrap().insert(key.to_string(), value.to_string());
	Ok(())
}

pub fn clear_custom_headers() {
    CUSTOM_HEADERS.write().unwrap().clear();
}

fn inject_custom_headers(headers: &mut HeaderMap) {
    let custom = CUSTOM_HEADERS.read().unwrap();
    if custom.is_empty() { return; }

    for (k, v) in custom.iter() {
        match (HeaderName::try_from(k.as_str()), HeaderValue::try_from(v.as_str())) {
            (Ok(name), Ok(value)) => {
                if !headers.contains_key(&name) {
                    headers.insert(name, value);
                }
                // در غیر این صورت هدر تکراری با پیش‌فرض است و نادیده گرفته می‌شود
            }
            _ => {
                eprintln!("[⚠️] Invalid custom header skipped: '{}: {}'", k, v);
            }
        }
    }
}

/// تابع جدید برای گرفتن تعداد هدرهای سفارشی
pub fn get_custom_headers_len() -> usize {
    CUSTOM_HEADERS.read().unwrap().len()
}

//inject_browser_headers()

//inject_json_headers()

//inject_image_headers()

//inject_download_headers()
