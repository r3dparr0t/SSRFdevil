// src/engine/proxy_engine.rs
use reqwest::{Client, Proxy};
use std::{
    sync::{LazyLock, atomic::{AtomicUsize, AtomicBool, Ordering}, RwLock as StdRwLock, Arc},
    {fs, thread}
};
use crate::engine::request_engine::EngineConfig;
use indicatif::{ProgressBar, ProgressStyle};
use futures::stream::{FuturesUnordered, StreamExt};
use tokio::{
    sync::{mpsc::{self, Sender, Receiver},Mutex},
    net::TcpStream,
    time::{timeout, Duration}
};
use crossterm::{
    event::{self, Event, KeyCode},
    terminal,
};

//const PROXY_PROBE_URL: &str = "https://cloudflare.com/cdn-cgi/trace";
const MAX_CONCURRENT_PROBES: usize = 100;

// ۱. ذخیره‌سازی آدرس متنی پروکسی‌های زنده
static VALIDATED_PROXIES: LazyLock<StdRwLock<Vec<String>>> =
    LazyLock::new(|| StdRwLock::new(Vec::new()));

static NEXT_INDEX: AtomicUsize = AtomicUsize::new(0);
static CANCEL_PROBING: AtomicBool = AtomicBool::new(false);

// پرچم جداگانه برای خاموش کردن قطعی listener thread، صرف‌نظر از اینکه کاربر q زده یا نه
static STOP_LISTENER: AtomicBool = AtomicBool::new(false);

// ۲. استخر گلوبال که قابلیت مقداردهی و ریست شدن دارد
pub static GLOBAL_POOL: LazyLock<StdRwLock<Option<DynamicProxyPool>>> = 
    LazyLock::new(|| StdRwLock::new(None));

/// -------------------------------------------------------------------
/// بخش اول: اسکنر و فیلتر پروکسی‌های خام
/// -------------------------------------------------------------------
pub async fn load_proxies_from_file(path: &str, cfg: &EngineConfig) -> usize {
    println!("[⚙️ DEBUG] load_proxies_from_file() triggered. Target path: {}", path);

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
    if total_loaded == 0 {
        println!("[⚠️] Proxy list is empty.");
        return 0;
    }

    println!("\n[🤖] Let's check your proxies... I'm going to drop the dead ones!\n[💡] Bored? Type 'q' and press Enter at any time to save live ones and quit scanning!");
    CANCEL_PROBING.store(false, Ordering::SeqCst);
    STOP_LISTENER.store(false, Ordering::SeqCst);

    // ورود به raw mode فقط برای طول عمر اسکن؛ این باعث می‌شه ورودی ترمینال
    // به‌صورت کاراکتر به کاراکتر و بدون بافر خط به این thread برسه،
    // بدون این‌که کنسول اصلی که بعداً read_line صدا می‌زنه رو مختل کنه —
    // چون قبل از خروج از این تابع، دقیقاً همین حالت رو خاموش می‌کنیم.
    let _ = terminal::enable_raw_mode();

    let listener = thread::spawn(move || {
        while !STOP_LISTENER.load(Ordering::SeqCst) {
            // poll غیربلاکه با تایم‌اوت کوتاه؛ یعنی این thread هیچ‌وقت
            // برای همیشه رو stdin گیر نمی‌کنه و همیشه در کمتر از ۱۲۰ms
            // می‌تونه به پرچم خاموشی واکنش نشون بده.
            match event::poll(Duration::from_millis(120)) {
                Ok(true) => {
                    if let Ok(Event::Key(key)) = event::read() {
                        if matches!(key.code, KeyCode::Char('q') | KeyCode::Char('Q')) {
                            println!("\n[⚠️] Emergency stop signal received! Wrapping up current probes...");
                            CANCEL_PROBING.store(true, Ordering::SeqCst);
                            break;
                        }
                    }
                }
                Ok(false) => continue,
                Err(_) => break, // اگر ترمینال دیگه در دسترس نبود، thread رو تمیز ببند
            }
        }
    });

    let bar = ProgressBar::new(total_loaded as u64);
    bar.set_style(
        ProgressStyle::default_bar()
            .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} | Live found: {msg}")
            .unwrap()
            .progress_chars("█|░")
    );

    let mut active_tasks = FuturesUnordered::new();
    let mut tested_count = 0;
    let mut live_list: Vec<String> = Vec::new();
    let mut live_count = 0;

    bar.set_message("0");

    while tested_count < total_loaded || !active_tasks.is_empty() {
        if CANCEL_PROBING.load(Ordering::SeqCst) { break; }

        while active_tasks.len() < MAX_CONCURRENT_PROBES && tested_count < total_loaded {
            if CANCEL_PROBING.load(Ordering::SeqCst) { break; }

            let url = raw_urls[tested_count].clone();
            active_tasks.push(async move {
                probe_proxy_only(url).await
            });
            tested_count += 1;
        }

        if let Some(opt_result) = active_tasks.next().await {
            bar.inc(1);
            if let Some(url) = opt_result {
                live_count += 1;
                bar.set_message(live_count.to_string());
                live_list.push(url);
            }
        }
    }

    // اسکن (چه با q چه با اتمام طبیعی) اینجا قطعاً تموم شده.
    // قبل از هر چیز دیگه‌ای، listener رو خاموش و join می‌کنیم تا
    // stdin کاملاً و بدون رقیب به کنسول اصلی برگرده.
    STOP_LISTENER.store(true, Ordering::SeqCst);
    let _ = listener.join();
    let _ = terminal::disable_raw_mode();

    if CANCEL_PROBING.load(Ordering::SeqCst) {
        bar.finish_with_message(format!("{} (Scan cancelled by user)", live_count));
    } else {
        bar.finish_with_message(format!("{} (Scan completed)", live_count));
    }

    let final_live_count = live_list.len();
    
    // ذخیره آدرس‌ها
    {
        let mut guard = VALIDATED_PROXIES.write().unwrap();
        *guard = live_list;
        NEXT_INDEX.store(0, Ordering::SeqCst);
    }
    
    // 🚀 اینجاست که موتور رسماً استارت می‌خورد (باگ برطرف شده)
    if final_live_count > 0 {
        // ایجاد استخر با ۱۰ کلاینت آماده درجا، و بافر ۲۰۰ تایی
        let pool = DynamicProxyPool::new(10, 200, cfg.clone()).await;
        let mut global_guard = GLOBAL_POOL.write().unwrap();
        *global_guard = Some(pool);
        println!("[⚙️ POOL] Dynamic proxy pool securely initialized.");
    }
    
    final_live_count
}

// تست فوق‌سبک (فقط TCP Handshake)
async fn probe_proxy_only(url: String) -> Option<String> {
    // فرض بر این است که url فرمت آدرس پروکسی است (مثلاً 1.2.3.4:8080)
    let addr = url.clone();
    
    // تلاش برای اتصال به سوکت پروکسی
    match timeout(Duration::from_millis(1500), TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => Some(url), // زنده است!
        _ => None,              // مرده است یا تایم‌اوت خورد
    }
}

pub fn get_proxies_len() -> usize {
    let pool = match VALIDATED_PROXIES.read() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner()
    };
    pool.len()
}

pub fn clear_proxies() {
    let mut guard = VALIDATED_PROXIES.write().unwrap();
    guard.clear();
    NEXT_INDEX.store(0, Ordering::SeqCst);
    
    // پاک کردن استخر کلاینت‌ها
    let mut global_guard = GLOBAL_POOL.write().unwrap();
    *global_guard = None;
}

/// -------------------------------------------------------------------
/// بخش دوم: استخر لغزنده و پویای کلاینت‌ها
/// -------------------------------------------------------------------
#[derive(Clone)]
pub struct DynamicProxyPool {
    receiver: Arc<Mutex<Receiver<Client>>>,
}

impl DynamicProxyPool {
    pub async fn new(initial_boot_size: usize, buffer_capacity: usize, config: EngineConfig) -> Self {
        let (tx, rx) = mpsc::channel::<Client>(buffer_capacity);
        
        let bootstrap_urls = {
            let proxies = VALIDATED_PROXIES.read().unwrap();
            let limit = std::cmp::min(initial_boot_size, proxies.len());
            proxies[0..limit].to_vec()
        };

        for url in bootstrap_urls {
            if let Some(client) = Self::build_client(&url, &config) {
                let _ = tx.try_send(client);
            }
            NEXT_INDEX.fetch_add(1, Ordering::SeqCst);
        }

        let bg_tx = tx.clone();
        tokio::spawn(async move {
            Self::filler_worker(bg_tx, config).await;
        });

        DynamicProxyPool {
            receiver: Arc::new(Mutex::new(rx)),
        }
    }

    pub async fn pick(&self) -> Option<Client> {
        let mut rx = self.receiver.lock().await;
        rx.recv().await
    }

    async fn filler_worker(tx: Sender<Client>, cfg: EngineConfig) {
        loop {
            match tx.reserve().await {
                Ok(permit) => {
                    if let Some(client) = Self::create_next_client(&cfg) {
                        permit.send(client);
                    } else {
                        tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
                    }
                }
                Err(_) => break, // توقف تزریق در صورت بسته شدن کانال
            }
        }
    }

    fn create_next_client(cfg: &EngineConfig) -> Option<Client> {
        let proxies = VALIDATED_PROXIES.read().unwrap();
        let total = proxies.len();
        if total == 0 { return None; }

        let idx = NEXT_INDEX.fetch_add(1, Ordering::SeqCst) % total;
        let url = &proxies[idx];
        Self::build_client(url, cfg)
    }

    fn build_client(url: &str, cfg: &EngineConfig) -> Option<Client> {
        if let Ok(proxy_obj) = Proxy::all(url) {
            Client::builder()
                .proxy(proxy_obj)
                .timeout(cfg.timeout)
                .danger_accept_invalid_certs(!cfg.verify_tls)
                .build()
                .ok()
        } else {
            None
        }
    }
}

/// -------------------------------------------------------------------
/// بخش سوم: تابع دسترسی سریع برای موتور ریکوئست
/// -------------------------------------------------------------------
pub async fn pick() -> Option<Client> {
    // گرفتن یک کپی از Arc به صورت همگام تا ران‌تایم بلاک نشود
    let pool_opt = {
        let guard = GLOBAL_POOL.read().unwrap();
        guard.clone()
    };
    
    // برداشتن کلاینت به صورت کاملاً غیرهمگام
    if let Some(pool) = pool_opt {
        pool.pick().await
    } else {
        None
    }
}
