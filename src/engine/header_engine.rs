// engine/header_engine.rs
use reqwest::header::{
	HeaderMap, HeaderValue,
	ACCEPT,
	ACCEPT_LANGUAGE,
	ACCEPT_ENCODING
};

pub fn inject(headers: &mut HeaderMap) {
    // فعلاً پروفایل بومی کروم را تزریق می‌کند
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,image/avif,image/webp,*/*;q=0.8"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
    headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("document"));
	// هدرهای امنیتی مدرن مرورگرها برای دور زدن مکانیزم‌های تشخیص بات
	headers.insert("Sec-Fetch-Mode", HeaderValue::from_static("navigate"));
	headers.insert("Sec-Fetch-Site", HeaderValue::from_static("none"));
	headers.insert("Sec-Fetch-User", HeaderValue::from_static("?1"));
	headers.insert("Upgrade-Insecure-Requests", HeaderValue::from_static("1"));
	headers.insert(ACCEPT_ENCODING, HeaderValue::from_static("gzip, deflate, br"));
	headers.insert("Connection", HeaderValue::from_static("keep-alive"));
	headers.insert("Cache-Control", HeaderValue::from_static("max-age=0"));
}
