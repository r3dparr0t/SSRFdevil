// src/engine/proxy_engine.rs
use reqwest::{Client, Proxy};
use std::sync::{LazyLock, atomic::{AtomicUsize, AtomicBool, Ordering}, RwLock as StdRwLock};
use crate::engine::request_engine::{EngineConfig, RedirectPolicy};
use indicatif::{ProgressBar, ProgressStyle};
use futures::stream::{FuturesUnordered, StreamExt};
use std::{fs, thread, io::{self, Read}};

const PROXY_PROBE_URL: &str = "https://cloudflare.com/cdn-cgi/trace";
const MAX_CONCURRENT_PROBES: usize = 100; // افزایش کانکرنسی به دلیل استفاده از روش سبک‌تر

// ذخیره‌سازی پروکسی‌های سبک (Proxy) به همراه آدرس متنی آن‌ها
static LIVE_PROXIES: LazyLock<StdRwLock<Vec<(Proxy, String)>>> =
    LazyLock::new(|| StdRwLock::new(Vec::new()));

static NEXT_INDEX: AtomicUsize = AtomicUsize::new(0);
static CANCEL_PROBING: AtomicBool = AtomicBool::new(false);

pub async fn load_proxies_from_file(path: &str, cfg: &EngineConfig) -> usize {
    println!("[⚙️ DEBUG] load_proxies_from_file() triggered. Target path: {}", path);

    println!("[⚙️ DEBUG] Reading proxy file contents into memory...");
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(e) => {
            println!("[❌] Cannot read file: {}", e);
            return 0;
        }
    };

    let raw_urls: Vec<String> = content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    let total_loaded = raw_urls.len();
    println!("[⚙️ DEBUG] Successfully parsed {} raw URLs from file.", total_loaded);

    if total_loaded == 0 {
        println!("[⚠️] Proxy list is empty.");
        return 0;
    }

    // ۲. نمایش پیغام و راهنمای کلید خروج اضطراری
    println!("\n[🤖] Let's check your proxies... I'm going to drop the dead ones!\n[💡] Bored? Type 'q' and press Enter at any time to save live ones and quit scanning!");

    CANCEL_PROBING.store(false, Ordering::SeqCst);

    thread::spawn(move || {
        let mut buffer = [0; 1];
        let mut stdin = io::stdin();
        while let Ok(n) = stdin.read(&mut buffer) {
            if n > 0 && (buffer[0] == b'q' || buffer[0] == b'Q') {
                println!("\n[⚠️] Emergency stop signal received! Wrapping up current probes...");
                CANCEL_PROBING.store(true, Ordering::SeqCst);
                break;
            }
        }
    });

    let bar = ProgressBar::new(total_loaded as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} | Live found: {msg}")
            .unwrap()
            .progress_chars("#>-")
    );

    let mut active_tasks = FuturesUnordered::new();
    let mut tested_count = 0;
    let mut live_list: Vec<(Proxy, String)> = Vec::new();
    let mut live_count = 0;

    bar.set_message("0");

    while tested_count < total_loaded || !active_tasks.is_empty() {
        if CANCEL_PROBING.load(Ordering::SeqCst) {
            break;
        }

        while active_tasks.len() < MAX_CONCURRENT_PROBES && tested_count < total_loaded {
            if CANCEL_PROBING.load(Ordering::SeqCst) {
                break;
            }

            let url = raw_urls[tested_count].clone();
            let cfg_inner = cfg.clone();
            
            active_tasks.push(async move {
                probe_proxy_only(url, cfg_inner).await
            });
            tested_count += 1;
        }

        if let Some(opt_result) = active_tasks.next().await {
            bar.inc(1);
            if let Some((proxy_obj, url)) = opt_result {
                live_count += 1;
                bar.set_message(live_count.to_string());
                live_list.push((proxy_obj, url));
            }
        }
    }

    if CANCEL_PROBING.load(Ordering::SeqCst) {
        bar.finish_with_message(format!("{} (Scan cancelled by user)", live_count));
    } else {
        bar.finish_with_message(format!("{} (Scan completed)", live_count));
    }

    let final_live_count = live_list.len();
    println!(
        "\n[✅] Finalizing... Kept: {} live nodes. Dead/Unreached nodes filtered out.", 
        final_live_count
    );

    {
        println!("[⚙️ DEBUG] Locking sliding pool to update live proxies list...");
        let mut guard = LIVE_PROXIES.write().unwrap();
        *guard = live_list;
        NEXT_INDEX.store(0, Ordering::SeqCst);
        println!("[⚙️ DEBUG] Update finished. Sliding pool index reset to 0.");
    }

    final_live_count
}

// چرخیدن روی استخر و تحویل شیء سبک Proxy
pub async fn pick() -> Option<Proxy> {
    let pool = LIVE_PROXIES.read().unwrap();
    let pool_len = pool.len();

    if pool_len == 0 {
        return None;
    }

    let current_idx = NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
    let target_idx = current_idx % pool_len;

    let (proxy_obj, url) = &pool[target_idx];
    println!(
        "[⚙️ PROXY] Sliding Pool rotating to index #{}: {}", 
        target_idx, url
    );

    // از کلونینگ سبک استفاده می‌کنیم
    Some(proxy_obj.clone())
}

// بررسی سریع زنده بودن پروکسی با یک کلاینت یکبار مصرفِ سبک بدون فعال‌سازی موتورهای اضافی دیتابیس
async fn probe_proxy_only(url: String, cfg: EngineConfig) -> Option<(Proxy, String)> {
    let proxy = reqwest::Proxy::all(&url).ok()?;

    // فقط برای تست سریع
    let test_client = Client::builder()
        .timeout(std::time::Duration::from_millis(1500)) 
        .proxy(proxy.clone())
        .danger_accept_invalid_certs(!cfg.verify_tls)
        .build()
        .ok()?;

    let response = test_client.get(PROXY_PROBE_URL).send().await.ok()?;
    if response.status().is_success() || response.status().is_redirection() {
        // بازگرداندن پروکسی آماده به همراه آدرس جهت ذخیره
        Some((proxy, url))
    } else {
        None
    }
}

pub async fn clear_proxies() {
    println!("[⚙️ DEBUG] clear_proxies() called. Purging sliding pool...");
    let mut guard = LIVE_PROXIES.write().unwrap();
    guard.clear();
    NEXT_INDEX.store(0, Ordering::SeqCst);
    println!("[⚙️ DEBUG] Sliding pool is now 100% clean.");
}

pub fn get_proxies_len() -> usize {
    let pool = match LIVE_PROXIES.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    };
    pool.len()
}
