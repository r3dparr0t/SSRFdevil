// crawler/crawler.rs
use scraper::{Html, Selector};
use url::Url;
use std::collections::HashSet;
use crate::engine::{
	request_engine::RequestEngine,
	request::RequestData
};
use reqwest::{Method,header::HeaderMap};

// پارامترهایی که احتمال SSRF دارن
const SSRF_PARAMS: &[&str] = &[
    "url", "dest", "redirect", "next", "path",
    "return", "return_to", "out", "view", "to",
    "image", "src", "source", "target", "host",
    "fetch", "proxy", "uri", "ref", "load",
];

const SELECTORS: &[(&str, &str, bool)] = &[
    ("a[href]", "href", true),
    ("form[action]", "action", true),
    ("img[src]", "src", false),
    ("iframe[src]", "src", false),
    ("script[src]", "src", false),
    ("video[src]", "src", false),
    ("audio[src]", "src", false),
    ("source[src]", "src", false),
    ("embed[src]", "src", false),
    ("object[data]", "data", false),
    ("link[href]", "href", false),
    ("input[formaction]", "formaction", false),
    ("button[formaction]", "formaction", false),
];

pub struct Crawler {
    engine: RequestEngine,
    visited: HashSet<Url>,
    targets: Vec<Url>,
}

impl Crawler {
    pub fn new(engine: RequestEngine) -> Self {
        Crawler {
            engine,
            visited: HashSet::new(),
            targets: Vec::new(),
        }
    }

    pub fn targets(&self) -> &[Url] {
        &self.targets
    }

    pub fn targets_mut(&mut self) -> &mut Vec<Url> {
        &mut self.targets
    }
    
    pub async fn crawl(&mut self, target: &Url) -> Vec<Url> {
        if self.visited.contains(target) {
            return vec![];
        }
        self.visited.insert(target.clone());
        
        // ساخت request
        let req = RequestData {
            method: Method::GET,
            url: target.clone(),
            headers: HeaderMap::new(),
            body: None,
        };

        // ارسال
        let response = match self.engine.send(req).await {
            Ok(r) => r,
            Err(_) => return vec![],
        };

        // parse HTML
        let html = match String::from_utf8(response.body) {
            Ok(s) => s,
            Err(_) => return vec![],
        };
        self.extract_targets(&html, target);
        self.targets.clone()
        //self.extract_ssrf_targets(&html, target)
    }


    fn extract_targets(&mut self, html: &str, base: &Url) {
        //self.targets.clear();
        let document = Html::parse_document(html);
        for (selector, attr, ssrf) in SELECTORS {
            self.extract_items(
                &document,
                base,
                selector,
                attr,
                *ssrf,
            );
        }
    }
    
    fn extract_items(
        &mut self,
        doc: &Html,
        base: &Url,
        selector: &str,
        attr: &str,
        check_ssrf: bool,
    ) {
        let selector = Selector::parse(selector).unwrap();

        for node in doc.select(&selector) {
            if let Some(value) = node.value().attr(attr) {
                if let Ok(url) = base.join(value) {
                
                    if check_ssrf && !self.has_ssrf_param(&url) {
                        continue;
                    }
                
                    if !self.targets.contains(&url) {
                        self.targets.push(url);
                    }
                }
            }
        }
    }

    fn has_ssrf_param(&self, url: &Url) -> bool {
        url.query_pairs()
            .any(|(key, _)| SSRF_PARAMS.contains(&key.as_ref()))
    }
}
