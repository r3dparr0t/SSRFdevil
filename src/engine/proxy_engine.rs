use reqwest::Client;
use std::sync::{LazyLock, atomic::{AtomicUsize, AtomicBool, Ordering}, RwLock as StdRwLock};
use crate::engine::request_engine::{EngineConfig, RedirectPolicy};
use std::fs;
use indicatif::{ProgressBar, ProgressStyle};
use futures::stream::{FuturesUnordered, StreamExt};
use std::thread;
use std::io::{self, Read};

const PROXY_PROBE_URL: &str = "https://cloudflare.com/cdn-cgi/trace";
const MAX_CONCURRENT_PROBES: usize = 50; 

// استخر لغزنده پروکسی‌های کاملاً زنده
static LIVE_PROXIES: LazyLock<StdRwLock<Vec<(Client, String)>>> =
    LazyLock::new(|| StdRwLock::new(Vec::new()));

static NEXT_INDEX: AtomicUsize = AtomicUsize::new(0);

// پرچم کنترل خروج اضطراری با کلید q
static CANCEL_PROBING: AtomicBool = AtomicBool::new(false);

pub async fn load_proxies_from_file(path: &str, cfg: &EngineConfig) -> usize {
    println!("[⚙️ DEBUG] load_proxies_from_file() triggered. Target path: {}", path);

    // ۱. خواندن فایل پروکسی‌ها به صورت کامل
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
    // ریست کردن پرچم انصراف قبل از شروع کار
    CANCEL_PROBING.store(false, Ordering::SeqCst);

    // ۳. لانچ کردن ترد شنود کیبورد در پس‌زمینه (Listener Thread)
    thread::spawn(move || {
        let mut buffer = [0; 1];
        let mut stdin = io::stdin();
        // خواندن بایت به بایت برای تشخیص زدن کلید q
        while let Ok(n) = stdin.read(&mut buffer) {
            if n > 0 && (buffer[0] == b'q' || buffer[0] == b'Q') {
                println!("\n[⚠️] Emergency stop signal received! Wrapping up current probes...");
                CANCEL_PROBING.store(true, Ordering::SeqCst);
                break;
            }
        }
    });

    // ۴. ساخت پروسس‌بار
    let bar = ProgressBar::new(total_loaded as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} | Live found: {msg}")
            .unwrap()
            .progress_chars("#>-")
    );

    let mut active_tasks = FuturesUnordered::new();
    let mut tested_count = 0;
    let mut live_list: Vec<(Client, String)> = Vec::new();
    let mut live_count = 0;

    bar.set_message("0");

    // ۵. شروع تست موازی با قابلیت خروج اضطراری آنی
    while tested_count < total_loaded || !active_tasks.is_empty() {
        
        // اگر کاربر در پس‌زمینه q زده بود، درجا متوقف کن
        if CANCEL_PROBING.load(Ordering::SeqCst) {
            break;
        }

        while active_tasks.len() < MAX_CONCURRENT_PROBES && tested_count < total_loaded {
            // یک بار دیگر قبل از ایجاد تسک جدید چک می‌کنیم تا بلافاصله متوقف شود
            if CANCEL_PROBING.load(Ordering::SeqCst) {
                break;
            }

            let url = raw_urls[tested_count].clone();
            let cfg_inner = cfg.clone();
            
            active_tasks.push(async move {
                build_and_probe_client(url, cfg_inner).await
            });
            tested_count += 1;
        }

        if let Some(opt_result) = active_tasks.next().await {
            bar.inc(1);
            if let Some((client, url)) = opt_result {
                live_count += 1;
                bar.set_message(live_count.to_string());
                live_list.push((client, url));
            }
        }
    }

    // بستن پروسس‌بار با پیام مناسب بسته به نوع خروج
    if CANCEL_PROBING.load(Ordering::SeqCst) {
        bar.finish_with_message(format!("{} (Scan cancelled by user)", live_count));
    } else {
        bar.finish_with_message(format!("{} (Scan completed)", live_count));
    }

    // ۶. ذخیره کردن همان تعداد پروکسی زنده که تا این لحظه یافت شده بودند
    let final_live_count = live_list.len();
    println!(
        "\n[✅] Finalizing... Kept: {} live nodes. Dead/Unreached nodes filtered out.", 
        final_live_count
    );

    {
        println!("[⚙️ DEBUG] Locking sliding pool to update live clients list...");
        let mut guard = LIVE_PROXIES.write().unwrap();
        *guard = live_list;
        NEXT_INDEX.store(0, Ordering::SeqCst);
        println!("[⚙️ DEBUG] Update finished. Sliding pool index reset to 0.");
    }

    final_live_count
}

pub async fn pick() -> Option<Client> {
    println!("[⚙️ DEBUG] pick() called. Attempting to lock sliding pool...");
    let pool = LIVE_PROXIES.read().unwrap();
    let pool_len = pool.len();

    println!("[⚙️ DEBUG] Current pool capacity: {} nodes.", pool_len);

    if pool_len == 0 {
        println!("[⚠️ DEBUG] pick() failed: Sliding pool is empty!");
        return None;
    }

    let current_idx = NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
    let target_idx = current_idx % pool_len;

    let (client, url) = &pool[target_idx];
    println!(
        "[⚙️ PROXY] Sliding Pool rotating to index #{}: {}", 
        target_idx, url
    );

    Some(client.clone())
}

async fn build_and_probe_client(url: String, cfg: EngineConfig) -> Option<(Client, String)> {
    let proxy = reqwest::Proxy::all(&url).ok()?;

    let test_builder = Client::builder()
        .timeout(std::time::Duration::from_millis(1500)) 
        .proxy(proxy)
        .cookie_store(true)
        .danger_accept_invalid_certs(!cfg.verify_tls);

    let test_client = if cfg.http2 {
        test_builder.use_rustls_tls().build().ok()?
    } else {
        test_builder.build().ok()?
    };

    let response = test_client.get(PROXY_PROBE_URL).send().await.ok()?;
    if response.status().is_success() || response.status().is_redirection() {
        build_final_client(&url, &cfg).ok().map(|c| (c, url))
    } else {
        None
    }
}

fn build_final_client(url: &str, cfg: &EngineConfig) -> Result<Client, reqwest::Error> {
    let proxy = reqwest::Proxy::all(url)?;

    let mut builder = Client::builder()
        .timeout(cfg.timeout)
        .proxy(proxy)
        .cookie_store(true)
        .danger_accept_invalid_certs(!cfg.verify_tls);

    builder = match cfg.redirects {
        RedirectPolicy::None => builder.redirect(reqwest::redirect::Policy::none()),
        RedirectPolicy::Follow => builder.redirect(reqwest::redirect::Policy::default()),
        RedirectPolicy::Limited(n) => builder.redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= n { attempt.stop() } else { attempt.follow() }
        })),
    };

    if cfg.http2 {
        builder = builder.use_rustls_tls();
    }

    builder.build()
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
        Err(poisoned) => {
            println!("[⚙️ DEBUG] Lock was poisoned, recovering guard...");
            poisoned.into_inner()
        }
    };
    pool.len()
}
