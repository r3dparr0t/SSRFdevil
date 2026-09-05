// src/engine/oob_engine.rs

use std::collections::HashMap;
use std::sync::{LazyLock, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::engine::request_engine::RequestEngine;
use crate::engine::request::RequestData;
use reqwest::header::HeaderMap;
use reqwest::Method;

#[derive(Debug, Clone)]
pub struct OobHit {
    pub correlation_id: String,
    pub hit_type: String, // "dns" | "http" | "unknown"
    pub remote: Option<String>,
    pub raw: String,
}

#[derive(Debug, Clone)]
struct OobRecord {
    correlation_id: String,
    rule_id: String,
    created_at: u64,
}

struct OobState {
    enabled: bool,
    base_url: String,
    poll_url: String,
    records: HashMap<String, OobRecord>,
}

// استفاده از LazyLock برای حل مشکل static + HashMap::new()
static OOB: LazyLock<RwLock<OobState>> = LazyLock::new(|| {
    RwLock::new(OobState {
        enabled: false,
        base_url: String::new(),
        poll_url: String::new(),
        records: HashMap::new(),
    })
});

/// فعال کردن سیستم OOB
pub fn enable(base_url: &str, poll_url: Option<&str>) {
    let mut state = OOB.write().unwrap();
    state.enabled = true;
    state.base_url = base_url.trim_end_matches('/').to_string();
    state.poll_url = poll_url
        .map(|u| u.to_string())
        .unwrap_or_else(|| format!("{}/poll", state.base_url));
    state.records.clear();
    println!("[OOB] Enabled → base: {} | poll: {}", state.base_url, state.poll_url);
}

pub fn disable() {
    let mut state = OOB.write().unwrap();
    state.enabled = false;
    state.records.clear();
    println!("[OOB] Disabled");
}

pub fn is_enabled() -> bool {
    OOB.read().unwrap().enabled
}

pub fn get_base_url() -> Option<String> {
    let state = OOB.read().unwrap();
    if state.enabled {
        Some(state.base_url.clone())
    } else {
        None
    }
}

/// تولید توکن یکتا برای استفاده در Lua (تابع oob_token)
pub fn generate_token(rule_id: &str) -> Option<String> {
    let mut state = OOB.write().unwrap();
    if !state.enabled {
        return None;
    }

    // توکن ۱۶ کاراکتری ثابت و تمیز
    let token = Uuid::new_v4().simple().to_string()[..16].to_string();

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    state.records.insert(
        token.clone(),
        OobRecord {
            correlation_id: token.clone(),
            rule_id: rule_id.to_string(),
            created_at: now,
        },
    );

    Some(token)
}

pub fn registered_count() -> usize {
    OOB.read().unwrap().records.len()
}

/// Poll کردن سرور OOB
pub async fn poll(engine: &RequestEngine) -> Vec<OobHit> {
    let (enabled, poll_url, records) = {
        let state = OOB.read().unwrap();
        if !state.enabled || state.records.is_empty() {
            return vec![];
        }
        (true, state.poll_url.clone(), state.records.clone())
    };

    if !enabled {
        return vec![];
    }

    let req = RequestData {
        method: Method::GET,
        url: match poll_url.parse() {
            Ok(u) => u,
            Err(_) => return vec![],
        },
        headers: HeaderMap::new(),
        body: None,
    };

    match engine.send(req).await {
        Ok(resp) => {
            let body = String::from_utf8_lossy(&resp.body).to_string();
            parse_hits(&body, &records)
        }
        Err(e) => {
            eprintln!("[OOB] Poll failed: {}", e);
            vec![]
        }
    }
}

fn parse_hits(body: &str, records: &HashMap<String, OobRecord>) -> Vec<OobHit> {
    let mut hits = Vec::new();

    for (corr_id, _) in records {
        if body.contains(corr_id) {
            hits.push(OobHit {
                correlation_id: corr_id.clone(),
                hit_type: "unknown".to_string(),
                remote: None,
                raw: body.to_string(),
            });
        }
    }

    hits
}

pub fn clear() {
    let mut state = OOB.write().unwrap();
    state.records.clear();
}
