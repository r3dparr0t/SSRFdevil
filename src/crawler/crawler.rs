// crawler/crawler.rs
use scraper::{Html, Selector, ElementRef};
use url::Url;
use std::collections::{HashSet, VecDeque};
use std::io::{BufWriter, Write};
use std::fs::File;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    "fetch", "proxy", "uri", "ref", "load",
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
        tags: Some(&[TargetTag::Image]), confidence: Some(90),
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
        selector: "video[src]", attr: "src", check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Video]), confidence: Some(90),
    },
    SelectorRule {
        selector: "audio[src]", attr: "src", check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Audio]), confidence: Some(80),
    },
    SelectorRule {
        selector: "source[src]", attr: "src", check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Media]), confidence: Some(70),
    },
    SelectorRule {
        selector: "embed[src]", attr: "src", check_ssrf: false,
        source: DiscoverySource::Embed, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Media]), confidence: Some(70),
    },
    SelectorRule {
        selector: "object[data]", attr: "data", check_ssrf: false,
        source: DiscoverySource::Object, kind: TargetKind::Resource,
        tags: Some(&[TargetTag::Media]), confidence: Some(70),
    },
    SelectorRule {
        selector: "link[href]", attr: "href", check_ssrf: false,
        source: DiscoverySource::Link, kind: TargetKind::Resource,
        tags: None, confidence: None,
    },
    SelectorRule {
        selector: "input[formaction]", attr: "formaction", check_ssrf: false,
        source: DiscoverySource::Form, kind: TargetKind::Endpoint,
        tags: Some(&[TargetTag::Form]), confidence: Some(100),
    },
    SelectorRule {
        selector: "button[formaction]", attr: "formaction", check_ssrf: false,
        source: DiscoverySource::Form, kind: TargetKind::Endpoint,
        tags: Some(&[TargetTag::Form]), confidence: Some(100),
    },
];

#[derive(Clone)]
pub struct CrawlerConfig {
    pub seed_urls: Vec<Url>,
    pub max_depth: usize,
    pub max_concurrent_requests: usize,
    pub allowed_domains: Vec<String>,
}

impl Default for CrawlerConfig {
    fn default() -> Self {
        CrawlerConfig {
            seed_urls: vec![],
            max_depth: 5,
            max_concurrent_requests: 10,
            allowed_domains: vec![],
        }
    }
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

    /// تشخیص کدگذاری و تبدیل بایت‌ها به رشته
    fn decode_body(body: &[u8], content_type: Option<&str>) -> String {
        let encoding = content_type
            .and_then(|ct| {
                ct.split(';')
                    .find(|part| part.trim().starts_with("charset="))
                    .and_then(|p| p.split('=').nth(1))
                    .map(|s| s.trim().to_uppercase())
            })
            .unwrap_or_default();

        // استفاده از encoding_rs برای تبدیل
        if let Some(coder) = encoding_rs::Encoding::for_label_no_replacement(encoding.as_bytes()) {
            coder.decode(body).0.into_owned()
        } else {
            // حدس از روی محتوای HTML (meta charset)
            if let Some(meta_encoding) = Self::extract_charset_from_html(body) {
                if let Some(coder) = encoding_rs::Encoding::for_label_no_replacement(meta_encoding.as_bytes()) {
                    return coder.decode(body).0.into_owned();
                }
            }
            // تلاش UTF-8 با جایگزینی کاراکترهای خراب
            String::from_utf8_lossy(body).into_owned()
        }
    }

    fn extract_charset_from_html(body: &[u8]) -> Option<String> {
        // جستجوی ساده برای <meta charset="..." یا <meta ... charset=...>
        let head = std::str::from_utf8(body).ok()?;
        let lower = head.to_lowercase();
        if let Some(start) = lower.find("charset=") {
            let rest = &lower[start + 8..];
            let end = rest.find(|c: char| c == '"' || c == '\'' || c == '>' || c == '/')?;
            Some(rest[..end].to_uppercase())
        } else {
            None
        }
    }

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

    fn extract_targets(&self, html: &str, url: &Url) -> Vec<Target> {
        let document = Html::parse_document(html);
        let mut new_targets = Vec::new();

        for rule in SELECTORS {
            self.collect_targets_from_rule(&document, url, rule, &mut new_targets);
        }
        self.collect_targets_from_forms(&document, url, &mut new_targets);

        new_targets
    }

    fn collect_targets_from_rule(
        &self,
        doc: &Html,
        base: &Url,
        rule: &SelectorRule,
        out: &mut Vec<Target>,
    ) {
        let Ok(sel) = Selector::parse(rule.selector) else { return };
        for node in doc.select(&sel) {
            if let Some(value) = node.value().attr(rule.attr) {
                if let Ok(url) = base.join(value) {
                    if rule.check_ssrf && !self.has_ssrf_param(&url) {
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

                    if out.iter().any(|t| t.url == url) { continue; }

                    let params = if rule.check_ssrf {
                        url.query_pairs()
                            .filter(|(k, _)| SSRF_PARAMS.contains(&k.as_ref()))
                            .map(|(k, _)| Param {
                                name: k.to_string(),
                                value: None,
                                location: ParamLocation::Query,
                            })
                            .collect()
                    } else {
                        Vec::new()
                    };

                    out.push(Target {
                        url: url.clone(),
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

    fn collect_targets_from_forms(&self, doc: &Html, base: &Url, out: &mut Vec<Target>) {
        let form_sel = Selector::parse("form").unwrap();
        let input_sel = Selector::parse("input, textarea, select").unwrap();

        for form in doc.select(&form_sel) {
            let action = form.value().attr("action").unwrap_or("");
            let method = form.value().attr("method").unwrap_or("get").to_uppercase();
            if let Ok(url) = base.join(action) {
                let params: Vec<Param> = form
                    .select(&input_sel)
                    .filter_map(|i| i.value().attr("name"))
                    .filter(|n| SSRF_PARAMS.contains(n))
                    .map(|s| Param {
                        name: s.to_string(),
                        value: None,
                        location: ParamLocation::Form,
                    })
                    .collect();
                if params.is_empty() { continue; }
                if out.iter().any(|t| t.url == url) { continue; }

                out.push(Target {
                    url,
                    kind: TargetKind::Endpoint,
                    method: if method == "POST" { Method::POST } else { Method::GET },
                    source: DiscoverySource::Form,
                    params,
                    meta: TargetMeta {
                        tags: vec![TargetTag::Form],
                        confidence: 100,
                        technologies: vec![],
                    },
                });
            }
        }
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

    // ==================== موتور خزیدن ====================
    pub async fn run(self: &Arc<Self>) {
        println!("[🚀] Crawler started...");

        {
            let file = File::create("crawl.log").expect("cannot create log file");
            *self.logger.lock().unwrap() = Some(BufWriter::new(file));
        }

        let queue = Arc::new(Mutex::new(VecDeque::new()));
        let active = Arc::new(AtomicBool::new(true));
        let notify = Arc::new(Notify::new());
        let allowed = self.allowed_domains_set();

        {
            let mut q = queue.lock().await;
            for url in &self.config.seed_urls {
                let normalized = normalize_url(url.clone());
                q.push_back((normalized.clone(), 0));
                self.log(&format!("[SEED] {}", normalized));
            }
            for domain in &allowed {
                for &scheme in &["http", "https"] {
                    if let Ok(url) = Url::parse(&format!("{}://{}/robots.txt", scheme, domain)) {
                        let normalized = normalize_url(url);
                        q.push_back((normalized.clone(), 0));
                        self.log(&format!("[ROBOTS] {}", normalized));
                    }
                }
            }
        }

        let worker_count = self.config.max_concurrent_requests;
        let mut handles = Vec::new();

        for id in 0..worker_count {
            let queue = Arc::clone(&queue);
            let active = Arc::clone(&active);
            let notify = Arc::clone(&notify);
            let this = Arc::clone(self);
            let allowed = allowed.clone();
            let max_depth = self.config.max_depth;

            handles.push(tokio::spawn(async move {
                loop {
                    let (url, depth) = {
                        let mut q = queue.lock().await;
                        match q.pop_front() {
                            Some(item) => item,
                            None => {
                                if !active.load(Ordering::SeqCst) { break; }
                                drop(q);
                                tokio::select! {
                                    _ = notify.notified() => {},
                                    _ = tokio::time::sleep(Duration::from_millis(500)) => {},
                                }
                                continue;
                            }
                        }
                    };

                    if depth > max_depth { continue; }

                    {
                        let mut visited = this.visited.lock().await;
                        if visited.contains(&url) {
                            continue;
                        }
                        visited.insert(url.clone());
                    }

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

                            if final_url.path() == "/robots.txt" {
                                let robot = Target {
                                    url: final_url.clone(),
                                    kind: TargetKind::Document,
                                    method: Method::GET,
                                    source: DiscoverySource::Robots,
                                    params: vec![],
                                    meta: TargetMeta {
                                        tags: vec![TargetTag::Robots],
                                        confidence: 100,
                                        technologies: vec![],
                                    },
                                };
                                this.targets.lock().await.push(robot);
                                this.log(&format!("[ROBOTS_OK] {}", final_url));
                                continue;
                            }

                            // استخراج content-type از هدرها
                            let content_type = resp.headers.get("content-type")
                                .and_then(|v| v.to_str().ok());
                            let html = Crawler::decode_body(&resp.body, content_type);

                            let new_links = this.extract_links(&html, &final_url);
                            let links_count = new_links.len();
                            {
                                let mut q = queue.lock().await;
                                for link in new_links {
                                    if this.is_allowed_domain(&link, &allowed) {
                                        q.push_back((link, depth + 1));
                                        active.store(true, Ordering::SeqCst);
                                    }
                                }
                                if links_count > 0 {
                                    notify.notify_waiters();
                                }
                            }

                            let new_targets = this.extract_targets(&html, &final_url);
                            let targets_count = new_targets.len();

                            this.log(&format!(
                                "[FETCH] {} | depth {} | {} new links | {} SSRF targets",
                                final_url, depth, links_count, targets_count
                            ));

                            if targets_count > 0 {
                                for t in &new_targets {
                                    println!("[🔥] SSRF target: {} (tags: {:?}, confidence: {})", t.url, t.meta.tags, t.meta.confidence);
                                }
                                this.targets.lock().await.extend(new_targets);
                            }
                        }
                        Err(e) => {
                            this.log(&format!("[ERROR] {} - {}", url, e));
                        }
                    }
                }
            }));
        }

        loop {
            let queue_empty = queue.lock().await.is_empty();
            if queue_empty && !active.load(Ordering::SeqCst) { break; }
            active.store(false, Ordering::SeqCst);
            notify.notify_waiters();
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        for h in &handles { h.abort(); }

        let total_pages = self.all_urls().await.len();
        let total_targets = self.targets().await.len();
        println!("\n[✅] Crawl finished. {} pages visited, {} SSRF targets found.", total_pages, total_targets);

        self.log(&format!("[DONE] {} pages, {} SSRF targets", total_pages, total_targets));
        *self.logger.lock().unwrap() = None;
    }
}

fn resolve_link_tags(element: &ElementRef) -> (Vec<TargetTag>, u8) {
    let rel = element.value().attr("rel").unwrap_or("").to_lowercase();
    match rel.as_str() {
        "stylesheet" => (vec![TargetTag::Css], 90),
        "manifest" => (vec![TargetTag::Manifest], 100),
        "canonical" => (vec![TargetTag::Canonical], 100),
        "icon" | "shortcut icon" | "apple-touch-icon" => (vec![TargetTag::Image], 80),
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
        "preload" | "prefetch" | "dns-prefetch" | "modulepreload" => {
            if let Some(as_type) = element.value().attr("as") {
                match as_type {
                    "script" => return (vec![TargetTag::Js], 70),
                    "style" => return (vec![TargetTag::Css], 90),
                    "image" => return (vec![TargetTag::Image], 80),
                    "font" => return (vec![TargetTag::Font], 80),
                    "fetch" => return (vec![TargetTag::Api], 90),
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
