// crawler/crawler.rs
use scraper::{Html, Selector, ElementRef};
use url::Url;
use std::collections::{HashSet, VecDeque};
use std::io::{BufWriter, Write};
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::sync::{Mutex, Notify};
use reqwest::{Method, header::HeaderMap};
use crate::engine::{
    request_engine::RequestEngine,
    request::RequestData,
};
use crate::crawler::crawler_config::{
    Target, TargetKind, DiscoverySource, TargetMeta, TargetTag, Param, ParamLocation,
};

const SSRF_PARAMS: &[&str] = &[
    "url", "dest", "redirect", "next", "path",
    "return", "return_to", "out", "view", "to",
    "image", "src", "source", "target", "host",
    "fetch", "proxy", "uri", "ref", "load", "callback", "webhook",
];

pub struct SelectorRule {
    pub selector: &'static str,
    pub attr: &'static str,
    pub check_ssrf: bool,
    pub source: DiscoverySource,
    pub kind: TargetKind,
    pub tags: Option<&'static [TargetTag]>,
    pub confidence: Option<u8>,
}

const SELECTORS: &[SelectorRule] = &[
    SelectorRule {
        selector: "a[href]", attr: "href", check_ssrf: true,
        source: DiscoverySource::Link, kind: TargetKind::Endpoint,
        tags: Some(&[TargetTag::Link]), confidence: Some(80),
    },
    SelectorRule {
        selector: "img[src]", attr: "src", check_ssrf: false,
        source: DiscoverySource::Image, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Image]), confidence: Some(50),
    },
    SelectorRule {
        selector: "iframe[src]", attr: "src", check_ssrf: false,
        source: DiscoverySource::Iframe, kind: TargetKind::Document,
        tags: Some(&[TargetTag::Iframe]), confidence: Some(90),
    },
    SelectorRule {
        selector: "script[src]", attr: "src", check_ssrf: false,
        source: DiscoverySource::Script, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Js]), confidence: Some(60),
    },
    SelectorRule {
        selector: "link[href]", attr: "href", check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: None, confidence: None,
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

    /// فاز اول: استخراج همه‌جانبه تمام لینک‌ها و فرم‌های داخلی جهت پیمایش ساختاری سایت بدون فیلتر کردن
    fn extract_links(&self, html: &str, base: &Url) -> Vec<Url> {
        let document = Html::parse_document(html);
        let allowed = self.allowed_domains_set();
        let mut links = Vec::new();

        for rule in SELECTORS {
            let Ok(sel) = Selector::parse(rule.selector) else { continue };
            for node in document.select(&sel) {
                if let Some(value) = node.value().attr(rule.attr) {
                    if let Ok(url) = base.join(value) {
                        if self.is_allowed_domain(&url, &allowed) {
                            links.push(normalize_url(url));
                        }
                    }
                }
            }
        }

        let form_sel = Selector::parse("form").unwrap();
        for form in document.select(&form_sel) {
            if let Some(action) = form.value().attr("action") {
                if let Ok(url) = base.join(action) {
                    if self.is_allowed_domain(&url, &allowed) {
                        links.push(normalize_url(url));
                    }
                }
            }
        }

        links
    }

    /// فاز دوم: اعمال شرایط و استخراج اهدافی که ارزش اسکن آسیب‌پذیری دارند
    fn extract_targets(&self, html: &str, url: &Url) -> Vec<Target> {
        let document = Html::parse_document(html);
        let mut new_targets = Vec::new();

        for rule in SELECTORS {
            let Ok(sel) = Selector::parse(rule.selector) else { continue };
            for node in document.select(&sel) {
                if let Some(value) = node.value().attr(rule.attr) {
                    if let Ok(target_url) = url.join(value) {
                        let has_ssrf = self.has_ssrf_param(&target_url);
                        
                        // فیلتر کردن شرایط: اگر قاعده نیاز به پارامتر SSRF دارد اما لینک فاقد آن است، رد شو
                        if rule.check_ssrf && !has_ssrf {
                            continue;
                        }

                        let (final_tags, confidence) = if rule.tags.is_none() || rule.confidence.is_none() {
                            if rule.selector == "link[href]" {
                                resolve_link_tags(&node)
                            } else {
                                (rule.tags.unwrap_or(&[]).to_vec(), rule.confidence.unwrap_or(50))
                            }
                        } else {
                            (rule.tags.unwrap().to_vec(), rule.confidence.unwrap())
                        };

                        //if new_targets.iter().any(|t: &T| t.url == target_url) { continue; }
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
                            method: Method::GET,
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

        // استخراج فرم‌ها به صورت ساختارمند
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

                //if new_targets.iter().any(|t| t.url == target_url) { continue; }
				if new_targets.iter().any(|t: &Target| t.url == target_url) { continue; }

                let has_interesting_param = params.iter().any(|p| SSRF_PARAMS.contains(&p.name.as_str()));
                let confidence = if has_interesting_param { 100 } else { 60 };

                new_targets.push(Target {
                    url: target_url,
                    kind: TargetKind::Endpoint,
                    method: if method == "POST" { Method::POST } else { Method::GET },
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

    pub async fn run(self: &Arc<Self>) {
        println!("[🚀] Crawler Discovery Engine started...");

        {
            let file = File::create("crawl.log").expect("cannot create log file");
            *self.logger.lock().unwrap() = Some(BufWriter::new(file));
        }

        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let active_tasks = Arc::new(AtomicUsize::new(0));
        let notify = Arc::new(Notify::new());
        let allowed = self.allowed_domains_set();

        {
            let mut q = queue.lock().await;
            for url in &self.config.seed_urls {
                let normalized = normalize_url(url.clone());
                q.push_back((normalized.clone(), 0));
                self.log(&format!("[SEED] {}", normalized));
            }
        }

        let worker_count = self.config.max_concurrent_requests;
        let mut handles = Vec::new();

        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let active_tasks = Arc::clone(&active_tasks);
            let notify = Arc::clone(&notify);
            let this = Arc::clone(self);
            let allowed = allowed.clone();
            let max_depth = self.config.max_depth;

            handles.push(tokio::spawn(async move {
                loop {
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
                    drop(q);

                    if depth > max_depth { continue; }

                    {
                        let mut visited = this.visited.lock().await;
                        if visited.contains(&url) { continue; }
                        visited.insert(url.clone());
                    }

                    active_tasks.fetch_add(1, Ordering::SeqCst);

                    let req = RequestData {
                        method: Method::GET,
                        url: url.clone(),
                        headers: HeaderMap::new(),
                        body: None,
                    };

                    match this.engine.send(req).await {
                        Ok(resp) => {
                            let final_url = resp.url.clone();
                            if final_url != url {
                                this.visited.lock().await.insert(final_url.clone());
                            }

                            let content_type = resp.headers.get("content-type").and_then(|v| v.to_str().ok());
                            let html = Crawler::decode_body(&resp.body, content_type);

                            // ۱. شخم زدن صفحات برای کشف کل لینک‌ها (بدون فیلتر)
                            let new_links = this.extract_links(&html, &final_url);
                            let links_count = new_links.len();
                            
                            {
                                let mut q = queue.lock().await;
                                for link in new_links {
                                    if this.is_allowed_domain(&link, &allowed) {
                                        q.push_back((link, depth + 1));
                                    }
                                }
                            }

                            // ۲. استخراج اهداف واجد شرایط آسیب‌پذیری
                            let new_targets = this.extract_targets(&html, &final_url);
                            let targets_count = new_targets.len();

                            if targets_count > 0 {
                                this.targets.lock().await.extend(new_targets);
                            }

                            // 🟢 نمایش وضعیت زنده در ترمینال (Live UX Reporting)
                            let current_queue_size = queue.lock().await.len();
                            let total_discovered_targets = this.targets.lock().await.len();
                            
                            let url_str = final_url.as_str();
                            let short_url = if url_str.len() > 45 { format!("{}...", &url_str[..45]) } else { url_str.to_string() };

                            println!(
                                "[Depth:{}] 🔍 Crawling: {} | 🧬 New: +{} Links, +{} Targets | 📋 Queue: {} | 🎯 Total Targets: {}",
                                depth, short_url, links_count, targets_count, current_queue_size, total_discovered_targets
                            );

                            this.log(&format!(
                                "[FETCH] {} | depth {} | {} new links | {} targets",
                                final_url, depth, links_count, targets_count
                            ));
                        }
                        Err(e) => {
                            this.log(&format!("[ERROR] {} - {}", url, e));
                        }
                    }

                    active_tasks.fetch_sub(1, Ordering::SeqCst);
                    notify.notify_waiters();
                }
            }));
        }

        loop {
            let queue_empty = queue.lock().await.is_empty();
            let active = active_tasks.load(Ordering::SeqCst);
            if queue_empty && active == 0 { break; }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        for h in &handles { h.abort(); }

        let total_pages = self.all_urls().await.len();
        let total_targets = self.targets().await.len();
        println!("\n[✅] Crawl finished. {} pages visited, {} potential targets mapped.", total_pages, total_targets);

        *self.logger.lock().unwrap() = None;
    }
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
