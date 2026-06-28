// engine/cookie_engine.rs
use reqwest::header::{HeaderMap, HeaderValue, COOKIE};

pub fn inject(headers: &mut HeaderMap) {
    // فعلاً تزریق ساده کوکی تا بعداً سشن واقعی بشود
    headers.insert(COOKIE, HeaderValue::from_static("session_id=ssrf_devil_active_backend_token"));
}
