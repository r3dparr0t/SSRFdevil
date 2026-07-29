// src/scanner/scanner.rs
use std::sync::Arc;
use tokio::sync::Semaphore;
use url::Url;
use reqwest::{Method, header::{HeaderMap, HeaderName, HeaderValue}};

use crate::{
    engine::{
        request_engine::RequestEngine,
        request::RequestData,
        response::ResponseData,
        rule::RuleFile,
    },
    crawler::crawler_config::Target,
    lua_engine::executor::{self, LuaPayload},
};

#[derive(Clone)]
pub struct ScannerConfig {
    pub max_concurrent: usize,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        ScannerConfig { max_concurrent: 20 }
    }
}

/// نتیجه‌ی اجرای یک payload روی شبکه. تشخیص false-positive و تحلیل بعدا
/// روی همین ساختار سوار میشه؛ فعلا فقط response خام رو نگه می‌داریم.
pub struct ScanResult {
    pub payload: LuaPayload,
    pub response: Option<ResponseData>,
    pub error: Option<String>,
}

pub struct Scanner {
    engine: RequestEngine,
    config: ScannerConfig,
}

impl Scanner {
    pub fn new(engine: RequestEngine, config: ScannerConfig) -> Self {
        Scanner { engine, config }
    }

    /// نقطه‌ی ورود واحد از کنسول: هم batch matching (executor، روی thread pool بلاکینگ)
    /// و هم ارسال واقعی payloadها رو یکجا انجام می‌ده. چیزی که قبلا تو console.rs
    /// پخش بود (spawn_blocking روی process_all_batches_single_pass + صدا زدن run)
    /// الان همینجا کپسوله شده؛ کنسول فقط `scanner.run_full_scan(targets, rules).await` صدا می‌زنه.
    pub async fn run_full_scan(self: &Arc<Self>, targets: Vec<Target>, rules: Vec<RuleFile>) -> Vec<ScanResult> {
        println!("[+] Got {} target(s). Matching selected rules with targets...", targets.len());

        let payloads = match tokio::task::spawn_blocking(move || {
            executor::process_all_batches_single_pass(&targets, &rules)
        }).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("❌ Task join error: {}", e);
                Vec::new()
            }
        };

        self.run(payloads).await
    }

    /// اجرای موازی همه‌ی payloadهای تولیدشده توسط executor روی شبکه.
    /// دقیقا الگوی کراولر: Arc<Self> + Semaphore برای محدود کردن Worker،
    /// delay_engine برای jitter بین درخواست‌ها.
    pub async fn run(self: &Arc<Self>, payloads: Vec<LuaPayload>) -> Vec<ScanResult> {
        if payloads.is_empty() {
            println!("[!] No payload to scan.");
            return Vec::new();
        }

        let semaphore = Arc::new(Semaphore::new(self.config.max_concurrent.max(1)));
        let mut handles = Vec::with_capacity(payloads.len());

        for payload in payloads {
            let sem = semaphore.clone();
            let this = Arc::clone(self);
            handles.push(tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.unwrap();
                crate::engine::delay_engine::wait().await;
                this.execute_one(payload).await
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for h in handles {
            match h.await {
                Ok(r) => results.push(r),
                Err(e) => eprintln!("    ❌ Scanner task join error: {}", e),
            }
        }

        let ok = results.iter().filter(|r| r.error.is_none()).count();
        println!("[+] Scan done: {}/{} request(s) succeeded.", ok, results.len());
        results
    }

    async fn execute_one(&self, payload: LuaPayload) -> ScanResult {
        match Self::build_request(&payload) {
            Ok(req) => match self.engine.send(req).await {
                Ok(resp) => {
                    println!("    [✓] {} {} -> {}", payload.method, payload.url, resp.status);
                    ScanResult { payload, response: Some(resp), error: None }
                }
                Err(e) => {
                    eprintln!("    ❌ Request failed for {}: {}", payload.url, e);
                    let err = e.to_string();
                    ScanResult { payload, response: None, error: Some(err) }
                }
            },
            Err(e) => {
                eprintln!("    ❌ Invalid payload {}: {}", payload.url, e);
                let err = e.to_string();
                ScanResult { payload, response: None, error: Some(err) }
            }
        }
    }

    /// دقیقا همون منطقی که قبلا run_payload تو executor.rs بود؛ فقط جابجا شده اینجا.
    fn build_request(payload: &LuaPayload) -> Result<RequestData, Box<dyn std::error::Error + Send + Sync>> {
        let url = Url::parse(&payload.url)?;
        let method = Method::from_bytes(payload.method.as_bytes())?;

        let mut headers = HeaderMap::new();
        for (k, v) in &payload.headers {
            if let (Ok(name), Ok(value)) = (
                HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                headers.insert(name, value);
            }
        }

        let body = payload.body.clone().map(|b| b.into_bytes());
        Ok(RequestData { method, url, headers, body })
    }
}
