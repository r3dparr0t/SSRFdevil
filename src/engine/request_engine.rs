// engine/request_engine.rs
use std::time::Duration;
use reqwest::Client;
use crate::engine::{
    request::RequestData,
    response::ResponseData,
    {delay_engine, header_engine, ua_engine, cookie_engine, trace_engine, proxy_engine}
};

#[derive(Clone)]
pub enum RedirectPolicy {
    None,
    Follow,
    Limited(usize),
}

#[derive(Clone)]
pub struct EngineConfig {
    pub timeout: Duration,
    pub redirects: RedirectPolicy,
    pub random_ua: bool,
    pub random_delay: bool,
    pub trace: bool,
    pub cookies: bool,
    pub proxy: bool,
    pub verify_tls: bool,
    pub http2: bool,
}

impl Default for EngineConfig {
    fn default() -> Self {
        EngineConfig {
            timeout: Duration::from_secs(10),
            redirects: RedirectPolicy::Limited(3),
            random_ua: true,
            random_delay: true,
            trace: false,
            cookies: false,
            proxy: false,
            http2: false,
            verify_tls: false,
        }
    }
}

#[derive(Clone)]
pub struct RequestEngine {
    // کلاینت پایه برای مواقعی که پروکسی خاموش است یا وجود ندارد
    base_client: Client,
    pub config: EngineConfig,
}

impl RequestEngine {
    pub fn new(config: EngineConfig) -> Self {
        let builder = Self::configure_builder(Client::builder(), &config);
        RequestEngine {
            base_client: builder.build().unwrap(),
            config,
        }
    }

    // متد کمکی برای تنظیم یکسان پارامترهای کلاینت‌ها
    fn configure_builder(mut builder: reqwest::ClientBuilder, config: &EngineConfig) -> reqwest::ClientBuilder {
        builder = builder.timeout(config.timeout).cookie_store(true);

        builder = match config.redirects {
            RedirectPolicy::None => builder.redirect(reqwest::redirect::Policy::none()),
            RedirectPolicy::Limited(n) => builder.redirect(reqwest::redirect::Policy::limited(n)),
            RedirectPolicy::Follow => builder.redirect(reqwest::redirect::Policy::default()),
        };

        if !config.verify_tls {
            builder = builder.danger_accept_invalid_certs(true);
        }

        builder
    }

    pub async fn send(&self, mut req_data: RequestData) -> Result<ResponseData, reqwest::Error> {
        // ۱. Delay Middleware
        if self.config.random_delay {
            delay_engine::wait().await;
        }
        // ۲. Injectors (تزریق به هدرها)
        if self.config.random_ua {
            ua_engine::inject(&mut req_data.headers);
        }
        
        header_engine::inject(&mut req_data.headers);

        if self.config.cookies {
            cookie_engine::inject(&mut req_data.headers);
        }

        // ۳. Trace Before
        if self.config.trace {
            trace_engine::before(&req_data);
        }

        // انتخاب هوشمند کلاینت:
        // اگر پروکسی فعال باشد، درجا یک کلاینت سبک و موقت با استفاده از پروکسیِ استخراج‌شده می‌سازیم.
        let client: Client = if self.config.proxy {
            match proxy_engine::pick().await {
                Some(proxy_obj) => {
                    let builder = Client::builder().proxy(proxy_obj);
                    // اعمال سایر تنظیمات به شکل یکنواخت روی کلاینت موقت
                    Self::configure_builder(builder, &self.config).build().unwrap()
                }
                None => {
                    println!("[⚠️] No proxy available, falling back to default client");
                    self.base_client.clone()
                }
            }
        } else { 
            self.base_client.clone()
        };

        // تبدیل مدل داده‌ی ما به درخواستِ واقعیِ Reqwest
        let mut builder = client.request(req_data.method, req_data.url)
            .headers(req_data.headers);

        if let Some(body_bytes) = req_data.body {
            builder = builder.body(body_bytes);
        }

        // شلیک نهایی (مشخص کردن نوع داده برای استنباط دقیق کامپایلر)
        let response: reqwest::Response = builder.send().await?;
        
        let final_url = response.url().clone();
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        
        // استخراج بایت‌ها به صورت صریح برای برطرف کردن ارور استنباط نوع
        let bytes_data = response.bytes().await?;
        let body = bytes_data.to_vec();
        
        let res_data = ResponseData {
            url: final_url,
            status,
            headers,
            body,
        };

        // ۴. Trace After
        if self.config.trace {
            trace_engine::after(&res_data);
        }

        Ok(res_data)
    }
}
