// engine/ua_engine.rs

use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};
use rand::distr::{Distribution, weighted::WeightedIndex};
use crate:: paths;
use std::{
    fs,
    sync::RwLock
};
// ---------------------------------------------------
// بخش بارگذاری و انتخاب یوزرایجنت وزنی
// ---------------------------------------------------

pub type UaEntry = (u32, String);

fn load_user_agents(min_weight: u32) -> Vec<UaEntry> {
    let content = match fs::read_to_string(paths::UA_FILE) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("[!] Warning: Could not read {}! Using safe fallback.", paths::UA_FILE);
            return vec![(100, "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36".to_string())];
        }
    };

    content
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() { return None; }
            if let Some((weight_str, ua)) = line.split_once('|') {
                if let Ok(weight) = weight_str.parse::<u32>() {
                    if weight >= min_weight {
                        return Some((weight, ua.to_string()));
                    }
                }
            }
            None
        })
        .collect()
}

fn get_random_weighted_ua(ua_list: &[UaEntry]) -> String {
    if ua_list.is_empty() {
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string();
    }
    let weights: Vec<u32> = ua_list.iter().map(|(w, _)| *w).collect();
    if let Ok(dist) = WeightedIndex::new(weights) {
        let mut rng = rand::rng(); 
        let index = dist.sample(&mut rng);
        ua_list[index].1.clone()
    } else {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36".to_string()
    }
}

static UA_LIST: RwLock<Vec<UaEntry>> = RwLock::new(Vec::new());

pub fn init() {
	//let settings = Settings::default(); 
	let settings = crate::config::APP_SETTINGS.get().unwrap().write().unwrap();
    let list = load_user_agents(settings.ua_profile.min_weight());
    *UA_LIST.write().unwrap() = list;
}

pub fn next() -> String {
    let list = UA_LIST.read().unwrap();
    get_random_weighted_ua(&list)
}

pub fn inject(headers: &mut HeaderMap) {
    // گرفتن یوزر ایجنت بعدی بر اساس وزن‌دهی از RwLock
    let next_ua = next();
    
    // تبدیل به HeaderValue و تزریق امن به ساختار هدرها
    if let Ok(header_value) = HeaderValue::from_str(&next_ua) {
        headers.insert(USER_AGENT, header_value);
    } else {
        // فال‌بک امن در صورت بروز هرگونه خطای انکودینگ عجیب در فایل متنی
        headers.insert(
            USER_AGENT, 
            HeaderValue::from_static("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        );
    }
}
