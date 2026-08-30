
// engine/cookie_engine.rs
use std::sync::RwLock;
use reqwest::header::{HeaderMap, HeaderValue, COOKIE};

static CURRENT_COOKIE: RwLock<Option<String>> = RwLock::new(None);

pub fn set_cookie(cookie_str: &str) {
    let mut cookie = CURRENT_COOKIE.write().unwrap();
    *cookie = Some(cookie_str.to_string());
}

pub fn clear_cookie() {
    let mut cookie = CURRENT_COOKIE.write().unwrap();
    *cookie = None;
}

pub fn get_cookie() -> Option<String> {
    let cookie = CURRENT_COOKIE.read().unwrap();
    cookie.clone()
}

pub fn inject(headers: &mut HeaderMap) {
    let cookie_opt = CURRENT_COOKIE.read().unwrap();
    if let Some(cookie_str) = &*cookie_opt {
        if let Ok(value) = HeaderValue::from_str(cookie_str) {
            headers.insert(COOKIE, value);
        }
    }
}
