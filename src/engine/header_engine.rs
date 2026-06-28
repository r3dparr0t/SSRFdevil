// engine/header_engine.rs
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE};
//use crate::engine::ua_engine;

pub fn inject(headers: &mut HeaderMap) {
    // فعلاً پروفایل بومی کروم را تزریق می‌کند
    headers.insert(ACCEPT, HeaderValue::from_static("text/html,application/xhtml+xml,image/avif,image/webp,*/*;q=0.8"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.5"));
    headers.insert("Sec-Fetch-Dest", HeaderValue::from_static("document"));
}
