// engine/proxy_engine.rs
use reqwest::Client;
use std::sync::{LazyLock, RwLock, atomic::{AtomicUsize, AtomicBool, Ordering}};
use crate::engine::request_engine::{EngineConfig, RedirectPolicy};
use std::fs;

// ظرفیت چانک‌های استخر فعال
const POOL_CAPACITY: usize = 50;
const REFILL_THRESHOLD: usize = 25;

// ۱. لیست کل آدرس‌های خام پروکسی به صورت رشته
static ALL_PROXY_URLS: LazyLock<RwLock<Vec<String>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));

// ۲. ایندکس پروکسی بعدی در فایل که باید کلاینت آن ساخته شود
static NEXT_PROXY_INDEX: AtomicUsize = AtomicUsize::new(0);

// ۳. استخر کلاینت‌های فعال آماده‌ی مصرف (با پاپ کردن، از اینجا کم می‌شوند)
static PROXY_CLIENTS: LazyLock<RwLock<Vec<Client>>> =
    LazyLock::new(|| RwLock::new(Vec::new()));

// ۴. وضعیت اتمیک برای اینکه فقط یک ترد همزمان مسئول شارژ پس‌زمینه باشد
static IS_REFILLING: AtomicBool = AtomicBool::new(false);

// ۵. ذخیره کانفیگ برای ساخت کلاینت‌های جدید در پس‌زمینه
static ENGINE_CONFIG_CACHE: LazyLock<RwLock<Option<EngineConfig>>> =
    LazyLock::new(|| RwLock::new(None));

pub fn load_proxies_from_file(path: &str, cfg: &EngineConfig) -> usize {
    // ریست کردن تمام وضعیت‌ها به حالت اولیه
    PROXY_CLIENTS.write().unwrap().clear();
    NEXT_PROXY_INDEX.store(0, Ordering::SeqCst);
    IS_REFILLING.store(false, Ordering::SeqCst);

    println!("[📂] Reading proxy list: {}", path);
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            println!("[❌] Cannot read file: {}", e);
            return 0;
        }
    };

    let urls: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    if urls.is_empty() {
        println!("[⚠️] Proxy list is empty.");
        return 0;
    }

    let n = urls.len();
    *ALL_PROXY_URLS.write().unwrap() = urls;
    *ENGINE_CONFIG_CACHE.write().unwrap() = Some(cfg.clone());

    // 🟢 پر کردن اولیه استخر (فقط ۵۰ تای اول)
    let mut initial_pool = Vec::new();
    let urls_back = ALL_PROXY_URLS.read().unwrap();
    let limit = std::cmp::min(n, POOL_CAPACITY);

    for i in 0..limit {
        if let Ok(client) = build_client_for(&urls_back[i], cfg) {
            initial_pool.push(client);
        }
    }
    
    NEXT_PROXY_INDEX.store(limit, Ordering::SeqCst);
    let built_count = initial_pool.len();
    *PROXY_CLIENTS.write().unwrap() = initial_pool;

    println!("[✅] Successfully cached {} URLs. Pool pre-filled with {} active clients.", n, built_count);
    n
}

/// انتخاب کلاینت: یک کلاینت را واقعاً از استخر پاپ می‌کند و برمی‌گرداند (مصرف واقعی)
pub fn pick() -> Option<Client> {
    let mut pool = PROXY_CLIENTS.write().unwrap();
    
    if pool.is_empty() {
        // اگر استخر کاملاً خالی بود، فلگ را دستی آزاد می‌کنیم تا شارژ فوری شلیک شود
        drop(pool);
        trigger_background_refill();
        return None; 
    }

    // پاپ کردن کلاینت (حذف از استخر و کاهش واقعی طول آن)
    let client = pool.pop();
    let current_len = pool.len();
    
    // همیشه قبل از فرخواندن تابع کمکی لاک را آزاد می‌کنیم تا بن‌بست ایجاد نشود
    drop(pool);

    // اگر موجودی کلاینت‌ها به زیر نصف (۲۵ تا) رسید، در پس‌زمینه چانک بعدی را بارگذاری کن
    if current_len <= REFILL_THRESHOLD {
        trigger_background_refill();
    }

    client
}

fn trigger_background_refill() {
    // تلاش برای تصاحب فلگ شارژ (اگر در حال شارژ است، دیگر تسکی شلیک نکن)
    if IS_REFILLING.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
        return;
    }

    // شلیک به پس‌زمینه توکیو (غیرمسدودکننده برای منو و ترد اصلی)
    tokio::spawn(async move {
        let urls = ALL_PROXY_URLS.read().unwrap();
        let total_urls = urls.len();
        let current_idx = NEXT_PROXY_INDEX.load(Ordering::SeqCst);

        // اگر به انتهای لیست پروکسی‌ها رسیدیم، دوباره از ایندکس صفر (چرخشی) شروع می‌کنیم
        let start_idx = if current_idx >= total_urls { 0 } else { current_idx };
        
        let cfg_opt = ENGINE_CONFIG_CACHE.read().unwrap();
        if let Some(cfg) = cfg_opt.as_ref() {
            let limit = std::cmp::min(total_urls - start_idx, POOL_CAPACITY);
            let mut new_clients = Vec::new();

            for i in 0..limit {
                let target_url = &urls[start_idx + i];
                if let Ok(client) = build_client_for(target_url, cfg) {
                    new_clients.push(client);
                }
            }

            if !new_clients.is_empty() {
                // به‌روزرسانی ایندکس برای چانک‌های بعدی
                NEXT_PROXY_INDEX.store(start_idx + limit, Ordering::SeqCst);
                
                // تزریق کلاینت‌های ترتیبی جدید به انتهای استخر فعال
                if let Ok(mut pool) = PROXY_CLIENTS.write() {
                    pool.extend(new_clients);
                }
            }
        }

        // آزاد کردن فلگ شارژ پس‌زمینه
        IS_REFILLING.store(false, Ordering::SeqCst);
    });
}

pub fn set_proxies(urls: Vec<String>, cfg: &EngineConfig) -> usize {
    let n = urls.len();
    *ALL_PROXY_URLS.write().unwrap() = urls;
    *ENGINE_CONFIG_CACHE.write().unwrap() = Some(cfg.clone());
    NEXT_PROXY_INDEX.store(0, Ordering::SeqCst);
    PROXY_CLIENTS.write().unwrap().clear();
    IS_REFILLING.store(false, Ordering::SeqCst);
    n
}

pub fn clear_proxies() {
    ALL_PROXY_URLS.write().unwrap().clear();
    PROXY_CLIENTS.write().unwrap().clear();
    *ENGINE_CONFIG_CACHE.write().unwrap() = None;
    NEXT_PROXY_INDEX.store(0, Ordering::SeqCst);
    IS_REFILLING.store(false, Ordering::SeqCst);
}

pub fn get_proxies_len() -> usize {
    ALL_PROXY_URLS.read().unwrap().len()
}

fn build_client_for(url: &str, cfg: &EngineConfig) -> Result<Client, String> {
    let proxy = reqwest::Proxy::all(url).map_err(|e| e.to_string())?;

    let mut builder = Client::builder()
        .timeout(cfg.timeout)
        .proxy(proxy)
        .cookie_store(true);

    builder = match cfg.redirects {
        RedirectPolicy::None => builder.redirect(reqwest::redirect::Policy::none()),
        RedirectPolicy::Follow => builder.redirect(reqwest::redirect::Policy::default()),
        RedirectPolicy::Limited(n) => builder.redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= n {
                attempt.stop()
            } else {
                attempt.follow()
            }
        })),
    };

    if !cfg.verify_tls {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if cfg.http2 {
        builder = builder.use_rustls_tls();
    }

    builder.build().map_err(|e| e.to_string())
}
