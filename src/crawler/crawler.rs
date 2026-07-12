// crawler/crawler.rs
use scraper::{Html, Selector, ElementRef};
use url::Url;
use std::{
	collections::{HashSet, VecDeque},
	io::{BufWriter, Write},
	fs::File,
	sync::{Arc, atomic::{AtomicUsize, Ordering}},
	time::Duration
};
use tokio::sync::{Mutex, Notify};
use reqwest::{Method, header::HeaderMap};
use crate::{
	engine::{
    	request_engine::RequestEngine,
    	request::RequestData,
    },
    crawler::crawler_config::{
    	Target, TargetKind, DiscoverySource,
    	TargetMeta, TargetTag, Param, ParamLocation,
	}
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind},
    terminal::{enable_raw_mode, disable_raw_mode}
};

const SSRF_PARAMS: &[&str] = &[
    "url", "dest", "redirect", "next", "path",
    "return", "return_to", "out", "view", "to",
    "image", "src", "source", "target", "host",
    "fetch", "proxy", "uri", "ref", "load", "callback", "webhook",
];

pub struct SelectorRule {
    pub selector: &'static str,
    pub attrs: &'static [&'static str],
    pub check_ssrf: bool,
    pub source: DiscoverySource,
    pub kind: TargetKind,
    pub tags: Option<&'static [TargetTag]>,
    pub confidence: Option<u8>,
}

const SELECTORS: &[SelectorRule] = &[
    // --- ۱. قوانین اختصاصی و دقیق ---
    SelectorRule {
        selector: "a[href]", attrs: &["href", "data-href", "data-url"], check_ssrf: true,
        source: DiscoverySource::Link, kind: TargetKind::Endpoint,
        tags: Some(&[TargetTag::Link]), confidence: Some(80),
    },
    SelectorRule {
        selector: "img[src]", attrs: &["src", "data-src"], check_ssrf: false,
        source: DiscoverySource::Image, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Image]), confidence: Some(90),
    },
    SelectorRule {
        selector: "iframe[src]", attrs: &["src"], check_ssrf: false,
        source: DiscoverySource::Iframe, kind: TargetKind::Document,
        tags: Some(&[TargetTag::Iframe]), confidence: Some(90),
    },
    SelectorRule {
        selector: "script[src]", attrs: &["src"], check_ssrf: false,
        source: DiscoverySource::Script, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Js]), confidence: Some(60),
    },
    SelectorRule {
        selector: "video[src]", attrs: &["src", "data-src"], check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Video]), confidence: Some(90),
    },
    SelectorRule {
        selector: "audio[src]", attrs: &["src", "data-src"], check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Audio]), confidence: Some(80),
    },
    SelectorRule {
        selector: "source[src]", attrs: &["src"], check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Media]), confidence: Some(70),
    },
    SelectorRule {
        selector: "embed[src]", attrs: &["src"], check_ssrf: false,
        source: DiscoverySource::Embed, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Media]), confidence: Some(70),
    },
    SelectorRule {
        selector: "object[data]", attrs: &["data"], check_ssrf: false,
        source: DiscoverySource::Object, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Media]), confidence: Some(70),
    },
    SelectorRule {
        selector: "link[href]", attrs: &["href"], check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: None, confidence: None,
    },
    SelectorRule {
        selector: "form[action]", attrs: &["action"], check_ssrf: false,
        source: DiscoverySource::Form, kind: TargetKind::Endpoint,
        tags: Some(&[TargetTag::Form]), confidence: Some(100),
    },
    SelectorRule {
        selector: "input[formaction]", attrs: &["formaction"], check_ssrf: false,
        source: DiscoverySource::Form, kind: TargetKind::Endpoint,
        tags: Some(&[TargetTag::Form]), confidence: Some(100),
    },
    SelectorRule {
        selector: "button[formaction]", attrs: &["formaction"], check_ssrf: false,
        source: DiscoverySource::Form, kind: TargetKind::Endpoint,
        tags: Some(&[TargetTag::Form]), confidence: Some(100),
    },

    // --- ۲. پوشش کامل تگ‌های عمومی ---
    SelectorRule {
        selector: "[data-url], [data-href]", attrs: &["data-url", "data-href"], check_ssrf: true,
        source: DiscoverySource::Link, kind: TargetKind::Endpoint,
        tags: Some(&[TargetTag::Link]), confidence: Some(70),
    },
    SelectorRule {
        selector: "[data-src]", attrs: &["data-src"], check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Link]), confidence: Some(60),
    },
    SelectorRule {
        selector: "[href]:not(a):not(link)", attrs: &["href"], check_ssrf: true,
        source: DiscoverySource::Link, kind: TargetKind::Endpoint,
        tags: Some(&[TargetTag::Link]), confidence: Some(60),
    },
    SelectorRule {
        selector: "[src]:not(img):not(script):not(iframe):not(video):not(audio):not(source):not(embed)", attrs: &["src"], check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Link]), confidence: Some(50),
    },
    SelectorRule {
        selector: "[action]:not(form)", attrs: &["action"], check_ssrf: false,
        source: DiscoverySource::Form, kind: TargetKind::Endpoint,
        tags: Some(&[TargetTag::Form]), confidence: Some(70),
    },
];

#[derive(Clone)]
pub struct CrawlerConfig {
    pub seed_urls: Vec<Url>,
    pub max_depth: usize,
    pub max_concurrent_requests: usize,
    pub allowed_domains: Vec<String>,
}

pub struct Crawler {
    engine: RequestEngine,
    config: CrawlerConfig,
    visited: Mutex<HashSet<Url>>,
    targets: Mutex<Vec<Target>>,
    logger: std::sync::Mutex<Option<BufWriter<File>>>,
}

fn resolve_link_tags(element: &ElementRef) -> (Vec<TargetTag>, u8) {
    let rel = element.value().attr("rel").unwrap_or("").to_lowercase();
    match rel.as_str() {
        "stylesheet" => (vec![TargetTag::Css], 50),
        "manifest" => (vec![TargetTag::Manifest], 100),
        "canonical" => (vec![TargetTag::Canonical], 80),
        "alternate" => {
            if let Some(typ) = element.value().attr("type") {
                match typ {
                    "application/rss+xml" => return (vec![TargetTag::Rss], 100),
                    "application/atom+xml" => return (vec![TargetTag::Atom], 100),
                    _ => {}
                }
            }
            (vec![TargetTag::Link], 60)
        }
        _ => (vec![TargetTag::Link], 50),
    }
}

fn normalize_url(mut url: Url) -> Url {
    url.set_fragment(None);
    if let Some(port) = url.port() {
        let default = match url.scheme() {
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        };
        if default == Some(port) { url.set_port(None).ok(); }
    }
    if let Some(host) = url.host_str().map(|h| h.to_lowercase()) {
        let rest = &url[url::Position::AfterHost..];
        if let Ok(new) = Url::parse(&format!("{}://{}{}", url.scheme(), host, rest)) {
            return new;
        }
    }
    url
}

impl Crawler {
    pub fn new(engine: RequestEngine, config: CrawlerConfig) -> Self {
        Crawler {
            engine,
            config,
            visited: Mutex::new(HashSet::new()),
            targets: Mutex::new(Vec::new()),
            logger: std::sync::Mutex::new(None),
        }
    }

    pub async fn run(self: &Arc<Self>) {
        // ۱. ریست کردن قطعی فلگ استاپ در بدو ورود
        crate::state::STOP_CRAWL.store(false, Ordering::SeqCst);

        // ۲. رم را کاملاً سفید می‌کنیم تا تداخل ایجاد نشود
        {
            self.visited.lock().await.clear();
            self.targets.lock().await.clear();
        }

        println!("[🦎] Crawler Discovery Engine started... Press 'q' anytime to safely stop.");
        
        let _ = enable_raw_mode();
        let terminal_guard = scopeguard::guard((), |_| {
            let _ = disable_raw_mode();
        });

        let stop_task = self.spawn_stop_listener();
        self.init_logger();

        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(Notify::new());
        let allowed = Arc::new(self.allowed_domains_set());

        let (worker_count, max_depth, max_runtime, retry_limit, save_state) = self.load_runtime_settings();

        // ۳. بازیابی استیت و بررسی هوشمند برای جلوگیری از بن‌بست ویزیت‌شده‌ها
        let mut state_recovered = false;
        if save_state {
            state_recovered = self.try_recover_state(save_state, &queue).await;
        }

        let mut q = queue.lock().await;
        // اگر قابلیت ذخیره فعال نبود، یا دیتابیس خالی بود، یا صف بازیابی‌شده خالی بود:
        if !state_recovered || q.is_empty() {
            q.clear();
            drop(q);
            
            // حیاتی: در ران جدید حتماً ویزیت‌شده‌های بازیابی‌شده قبلی هم باید از رم پاک شوند
            self.visited.lock().await.clear(); 
            
            if save_state {
                if let Ok(db) = sled::open(crate::paths::TARGETS_DB) {
                    db.remove("state:queue").ok();
                    db.remove("state:visited").ok();
                    let _ = db.flush();
                }
            }
            
            self.initialize_queue_with_seeds(&queue).await;
        } else {
            drop(q);
            println!("[⏳] Resuming previous crawl session safely...");
        }

        let start_time = std::time::Instant::now();
        let mut handles = Vec::new();

        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let active_tasks = Arc::clone(&active_tasks);
            let notify = Arc::clone(&notify);
            let this = Arc::clone(self);
            let allowed = Arc::clone(&allowed);

            handles.push(tokio::spawn(async move {
                loop {
                    if crate::state::STOP_CRAWL.load(Ordering::SeqCst) { break; }
                    if max_runtime > 0 && start_time.elapsed().as_secs() >= max_runtime {
                        println!("[🛑] Kill-Switch triggered: Reached max runtime limit ({}s)", max_runtime);
                        crate::state::STOP_CRAWL.store(true, Ordering::SeqCst);
                        break;
                    }

                    let mut q = queue.lock().await;
                    let item = q.pop_front();
                    
                    if item.is_none() {
                        if active_tasks.load(Ordering::SeqCst) == 0 {
                            drop(q);
                            notify.notify_waiters();
                            break;
                        }
                        drop(q);
                        tokio::select! {
                            _ = notify.notified() => {},
                            _ = tokio::time::sleep(Duration::from_millis(50)) => {},
                        }
                        continue;
                    }
                    
                    let (url, depth) = item.unwrap();
                    
                    if save_state {
                        this.save_queue_state(&q);
                    }
                    drop(q);

                    if depth > max_depth { continue; }

                    this.process_crawler_item(
                        url, 
                        depth, 
                        save_state, 
                        retry_limit, 
                        allowed.clone(), 
                        queue.clone(), 
                        active_tasks.clone(), 
                        notify.clone()
                    ).await;
                }
            }));
        }

        // حلقه مانیتورینگ اصلی منبع و وضعیت‌ها
        loop {
            let queue_empty = queue.lock().await.is_empty();
            let active = active_tasks.load(Ordering::SeqCst);
            let stop_triggered = crate::state::STOP_CRAWL.load(Ordering::SeqCst);
            
            if (queue_empty && active == 0) || stop_triggered { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // ۴. اگر کار طبیعی تمام شد و کاربر دکمه خروج را نزد، کش استیت را کامل پاک کن
        let user_stopped = crate::state::STOP_CRAWL.load(Ordering::SeqCst) && !queue.lock().await.is_empty();
        
        crate::state::STOP_CRAWL.store(true, Ordering::SeqCst);
        for h in &handles { h.abort(); }
        stop_task.abort();
        drop(terminal_guard);

        if !user_stopped {
            self.cleanup_state_on_finish(save_state);
        }

        let total_pages = self.all_urls().await.len();
        let total_targets = self.targets().await.len();
        println!("\n[✅] Crawl finished. {} pages visited, {} potential targets mapped.", total_pages, total_targets);

        crate::state::STOP_CRAWL.store(false, Ordering::SeqCst);
        *self.logger.lock().unwrap() = None;
    }

    fn log(&self, msg: &str) {
        let mut guard = self.logger.lock().unwrap();
        if let Some(ref mut writer) = *guard {
            let _ = writeln!(writer, "{}", msg);
            let _ = writer.flush();
        }
    }

    fn is_allowed_domain(&self, url: &Url, allowed: &HashSet<String>) -> bool {
        if let Some(domain) = url.domain() {
            let normalized = domain.trim_start_matches("www.");
            allowed.iter().any(|d| d.trim_start_matches("www.") == normalized)
        } else {
            false
        }
    }

    fn allowed_domains_set(&self) -> HashSet<String> {
        if self.config.allowed_domains.is_empty() {
            self.config.seed_urls.iter()
                .filter_map(|u| u.domain().map(|d| d.to_string()))
                .map(|d| d.trim_start_matches("www.").to_string())
                .collect()
        } else {
            self.config.allowed_domains.iter()
                .map(|d| d.trim_start_matches("www.").to_string())
                .collect()
        }
    }

    fn decode_body(body: &[u8], content_type: Option<&str>) -> String {
        let encoding = content_type
            .and_then(|ct| {
                ct.split(';')
                    .find(|part| part.trim().starts_with("charset="))
                    .and_then(|p| p.split('=').nth(1))
                    .map(|s| s.trim().to_uppercase())
            })
            .unwrap_or_default();

        if let Some(coder) = encoding_rs::Encoding::for_label_no_replacement(encoding.as_bytes()) {
            coder.decode(body).0.into_owned()
        } else {
            String::from_utf8_lossy(body).into_owned()
        }
    }

    fn extract_links(&self, html: &str, base: &Url) -> Vec<Url> {
        let document = Html::parse_document(html);
        let allowed = self.allowed_domains_set();
        let mut unique_links = HashSet::new();

        for rule in SELECTORS {
            let Ok(sel) = Selector::parse(rule.selector) else { continue };
            for node in document.select(&sel) {
                for &attr in rule.attrs {
                    if let Some(value) = node.value().attr(attr) {
                        let trimmed = value.trim();
                        if trimmed.is_empty() || trimmed.starts_with("javascript:") || trimmed.starts_with("data:") {
                            continue;
                        }
                        if let Ok(url) = base.join(trimmed) {
                            if self.is_allowed_domain(&url, &allowed) {
                                unique_links.insert(normalize_url(url));
                            }
                        }
                    }
                }
            }
        }

        let form_sel = Selector::parse("form").unwrap();
        for form in document.select(&form_sel) {
            if let Some(action) = form.value().attr("action") {
                if let Ok(url) = base.join(action.trim()) {
                    if self.is_allowed_domain(&url, &allowed) {
                        unique_links.insert(normalize_url(url));
                    }
                }
            }
        }

        static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
        let re = RE.get_or_init(|| {
            regex::Regex::new(r#"(?:"|')((?:https?://[^"'\s>]+)|(?:/[^"'\s>]{2,}))(?:"|')"#).unwrap()
        });

        for cap in re.captures_iter(html) {
            if let Some(matched) = cap.get(1) {
                let url_str = matched.as_str().trim();
                if let Ok(url) = base.join(url_str) {
                    if self.is_allowed_domain(&url, &allowed) {
                        unique_links.insert(normalize_url(url));
                    }
                }
            }
        }

        unique_links.into_iter().collect()
    }
    
    fn extract_targets(&self, html: &str, url: &Url) -> Vec<Target> {
        let document = Html::parse_document(html);
        let mut new_targets = Vec::new();

        for rule in SELECTORS {
            let Ok(sel) = Selector::parse(rule.selector) else { continue };
            for node in document.select(&sel) {
                for &attr in rule.attrs {
                    if let Some(value) = node.value().attr(attr) {
                        if let Ok(target_url) = url.join(value.trim()) {
                            let has_ssrf = self.has_ssrf_param(&target_url);
                            
                            if rule.check_ssrf && !has_ssrf {
                                continue;
                            }

                            let (final_tags, confidence) = if rule.tags.is_none() || rule.confidence.is_none() {
                                if rule.selector.contains("link[href]") {
                                    resolve_link_tags(&node)
                                } else {
                                    (rule.tags.unwrap_or(&[]).to_vec(), rule.confidence.unwrap_or(50))
                                }
                            } else {
                                (rule.tags.unwrap().to_vec(), rule.confidence.unwrap())
                            };

                            if new_targets.iter().any(|t: &Target| t.url == target_url) { continue; }

                            let params = target_url.query_pairs()
                                .map(|(k, _)| Param {
                                    name: k.to_string(),
                                    value: None,
                                    location: ParamLocation::Query,
                                })
                                .collect();

                            new_targets.push(Target {
                                url: target_url.clone(),
                                kind: rule.kind,
                                method: Method::GET.to_string(),
                                source: rule.source,
                                params,
                                meta: TargetMeta {
                                    tags: final_tags,
                                    confidence,
                                    technologies: vec![],
                                },
                            });
                        }
                    }
                }
            }
        }

        let form_sel = Selector::parse("form").unwrap();
        let input_sel = Selector::parse("input, textarea, select, hidden").unwrap();

        for form in document.select(&form_sel) {
            let action = form.value().attr("action").unwrap_or("");
            let method = form.value().attr("method").unwrap_or("get").to_uppercase();
            if let Ok(target_url) = url.join(action) {
                
                let params: Vec<Param> = form
                    .select(&input_sel)
                    .filter_map(|i| i.value().attr("name"))
                    .map(|s| Param {
                        name: s.to_string(),
                        value: None,
                        location: ParamLocation::Form,
                    })
                    .collect();

                if new_targets.iter().any(|t: &Target| t.url == target_url) { continue; }

                let has_interesting_param = params.iter().any(|p| SSRF_PARAMS.contains(&p.name.as_str()));
                let confidence = if has_interesting_param { 100 } else { 60 };

                new_targets.push(Target {
                    url: target_url,
                    kind: TargetKind::Endpoint,
                    method: if method == "POST" { Method::POST.to_string() } else { Method::GET.to_string() },
                    source: DiscoverySource::Form,
                    params,
                    meta: TargetMeta {
                        tags: vec![TargetTag::Form],
                        confidence,
                        technologies: vec![],
                    },
                });
            }
        }

        new_targets
    }

    fn has_ssrf_param(&self, url: &Url) -> bool {
        url.query_pairs().any(|(k, _)| SSRF_PARAMS.contains(&k.as_ref()))
    }

    pub async fn all_urls(&self) -> Vec<Url> {
        let visited = self.visited.lock().await;
        visited.iter().cloned().collect()
    }

    pub async fn targets(&self) -> Vec<Target> {
        let targets = self.targets.lock().await;
        targets.clone()
    }

    fn spawn_stop_listener(&self) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async {
            loop {
                if crate::state::STOP_CRAWL.load(Ordering::SeqCst) { break; }
                
                match event::poll(Duration::from_millis(50)) {
                    Ok(true) => {
                        if let Ok(Event::Key(key_event)) = event::read() {
                            if key_event.kind == KeyEventKind::Press {
                                if key_event.code == KeyCode::Char('q') || key_event.code == KeyCode::Char('Q') {
                                    print!("\r\n[🛑] Safe stop requested by user! Wrapping up active workers...\r\n");
                                    let _ = std::io::stdout().flush();
                                    crate::state::STOP_CRAWL.store(true, Ordering::SeqCst);
                                    break;
                                }
                            }
                        }
                    }
                    _ => {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
        })
    }

    fn init_logger(&self) {
        std::fs::create_dir_all(crate::paths::CRAWL_LOG_DIR).ok();
        let file = File::create(crate::paths::CRAWL_LOG).expect("cannot create log file");
        *self.logger.lock().unwrap() = Some(BufWriter::new(file));
    }

    fn load_runtime_settings(&self) -> (usize, usize, u64, u32, bool) {
        let settings = crate::config::APP_SETTINGS.get().unwrap().read().unwrap();
        (
            settings.threads as usize,
            settings.crawler_max_depth,
            settings.max_runtime,
            settings.retry as u32,
            settings.crawler_save_state,
        )
    }

    async fn try_recover_state(&self, save_state: bool, queue: &Mutex<VecDeque<(Url, usize)>>) -> bool {
        if !save_state { return false; }
        let mut state_recovered = false;
        
        if let Ok(db) = sled::open(crate::paths::TARGETS_DB) {
            if let Ok(Some(saved_queue_bytes)) = db.get("state:queue") {
                if let Ok(recovered_q) = serde_json::from_slice::<VecDeque<(Url, usize)>>(&saved_queue_bytes) {
                    if !recovered_q.is_empty() {
                        let mut q = queue.lock().await;
                        *q = recovered_q;
                        state_recovered = true;
                        println!("[⏳] Resumed crawler queue from saved state ({} items fetched)", q.len());
                    }
                }
            }
            if let Ok(Some(saved_visited_bytes)) = db.get("state:visited") {
                if let Ok(recovered_visited) = serde_json::from_slice::<HashSet<Url>>(&saved_visited_bytes) {
                    let mut v = self.visited.lock().await;
                    *v = recovered_visited;
                }
            }
        }
        state_recovered
    }

    async fn initialize_queue_with_seeds(&self, queue: &Mutex<VecDeque<(Url, usize)>>) {
        let mut q = queue.lock().await;
        for url in &self.config.seed_urls {
            let normalized = normalize_url(url.clone());
            q.push_back((normalized.clone(), 0));
            self.log(&format!("[SEED] {}", normalized));
        }
    }

    fn save_queue_state(&self, queue: &VecDeque<(Url, usize)>) {
        if let Ok(db) = sled::open(crate::paths::TARGETS_DB) {
            if let Ok(bytes) = serde_json::to_vec(queue) {
                db.insert("state:queue", bytes).ok();
            }
        }
    }

    fn cleanup_state_on_finish(&self, save_state: bool) {
        if save_state {
            if let Ok(db) = sled::open(crate::paths::TARGETS_DB) {
                db.remove("state:queue").ok();
                db.remove("state:visited").ok();
                let _ = db.flush();
            }
        }
    }

    async fn process_crawler_item(
        self: &Arc<Self>,
        url: Url,
        depth: usize,
        save_state: bool,
        retry_limit: u32,
        allowed: Arc<HashSet<String>>,
        queue: Arc<Mutex<VecDeque<(Url, usize)>>>,
        active_tasks: Arc<AtomicUsize>,
        notify: Arc<Notify>,
    ) {
        {
            let mut visited = self.visited.lock().await;
            if visited.contains(&url) { return; }
            visited.insert(url.clone());
            
            if save_state {
                if let Ok(db) = sled::open(crate::paths::TARGETS_DB) {
                    if let Ok(bytes) = serde_json::to_vec(&*visited) {
                        db.insert("state:visited", bytes).ok();
                    }
                }
            }
        }

        active_tasks.fetch_add(1, Ordering::SeqCst);
        let active_tasks_guard = {
            let active = active_tasks.clone();
            let n = notify.clone();
            scopeguard::guard((), move |_| {
                active.fetch_sub(1, Ordering::SeqCst);
                n.notify_waiters();
            })
        };

        let req = RequestData {
            method: Method::GET,
            url: url.clone(),
            headers: HeaderMap::new(),
            body: None,
        };

        let mut response_result = None;
        for attempt in 0..=retry_limit {
            if crate::state::STOP_CRAWL.load(Ordering::SeqCst) { break; }
            crate::engine::delay_engine::wait().await;

            match self.engine.send(req.clone()).await {
                Ok(resp) => {
                    response_result = Some(resp);
                    break;
                }
                Err(e) => {
                    if attempt == retry_limit {
                        self.log(&format!("[ERROR] {} - Max retries reached: {}", url, e));
                    } else {
                        self.log(&format!("[⚠️] Retry {}/{} for {} due to error: {}", attempt + 1, retry_limit, url, e));
                    }
                }
            }
        }

        if let Some(resp) = response_result {
            let final_url = resp.url.clone();
            if final_url != url {
                self.visited.lock().await.insert(final_url.clone());
            }

            let content_type = resp.headers.get("content-type").and_then(|v| v.to_str().ok());
            let html = Crawler::decode_body(&resp.body, content_type);

            let new_links = self.extract_links(&html, &final_url);
            let links_count = new_links.len();
            
            {
                let mut q = queue.lock().await;
                for link in new_links {
                    if self.is_allowed_domain(&link, &allowed) {
                        q.push_back((link, depth + 1));
                    }
                }
            }

            let new_targets = self.extract_targets(&html, &final_url);
            let targets_count = new_targets.len();

            if targets_count > 0 {
                let max_targets = crate::config::APP_SETTINGS.get().unwrap().read().unwrap().crawler_max_targets;
                let current_targets = self.targets.lock().await.len();

                if max_targets > 0 && current_targets + targets_count >= max_targets {
                    println!("[🛑] Kill-Switch triggered: Reached max targets limit ({})", max_targets);
                    crate::state::STOP_CRAWL.store(true, Ordering::SeqCst);
                }

                if let Ok(db) = sled::open(crate::paths::TARGETS_DB) {
                    for t in &new_targets {
                        let key = t.url.to_string();
                        if let Ok(val) = serde_json::to_vec(t) {
                            db.insert(key.as_bytes(), val).ok();
                        }
                    }
                }
                self.targets.lock().await.extend(new_targets);
            }

            let current_queue_size = queue.lock().await.len();
            let total_discovered_targets = self.targets.lock().await.len();
            
            let url_str = final_url.as_str();
            let short_url = if url_str.len() > 45 { format!("{}...", &url_str[..45]) } else { url_str.to_string() };

            println!(
                "[Depth:{}] 🔍 Crawling: {} | 🧬 New: +{} Links, +{} Targets | 📋 Queue: {} | 🎯 Total Targets: {}",
                depth, short_url, links_count, targets_count, current_queue_size, total_discovered_targets
            );

            self.log(&format!(
                "[FETCH] {} | depth {} | {} new links | {} targets",
                final_url, depth, links_count, targets_count
            ));
        }
        
        drop(active_tasks_guard); 
    }
}
