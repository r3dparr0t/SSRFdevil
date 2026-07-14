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
    client: Client,
    pub config: EngineConfig,
}

impl RequestEngine {
    pub fn new(config: EngineConfig) -> Self {
        let mut builder = Client::builder()
        	.timeout(config.timeout);
        	//.cookie_store(true);

        builder = match config.redirects {
            RedirectPolicy::None => builder.redirect(reqwest::redirect::Policy::none()),
            RedirectPolicy::Limited(n) => builder.redirect(reqwest::redirect::Policy::limited(n)),
            RedirectPolicy::Follow => builder.redirect(reqwest::redirect::Policy::default()),
        };
        //builder = builder.danger_accept_invalid_certs(true);
		if !config.verify_tls {
    		builder = builder.danger_accept_invalid_certs(true);
    	}
        // add cookie jar.
        builder = builder.cookie_store(true);
        // پروکسی دیگر اینجا bake نمی‌شود؛ چون هر پروکسی یک Client جداست
        // (به‌خاطر rotation)، انتخابش موقع send() از proxy_engine انجام می‌شود.
        RequestEngine {
            client: builder.build().unwrap(),
            config,
        }
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

        // انتخاب کلاینت: فقط وقتی پروکسی فعال است و pool خالی نیست، یک
        // کلاینتِ پروکسی‌دار تصادفی انتخاب می‌شود؛ در غیر این صورت کلاینت پیش‌فرض.
        let client = if self.config.proxy && proxy_engine::get_proxies_len() > 0 {
            proxy_engine::pick().unwrap_or_else(|| self.client.clone())
        } else {
            self.client.clone()
        };

        // تبدیل مدل داده‌ی ما به درخواستِ واقعیِ Reqwest
        let mut builder = client.request(req_data.method, req_data.url)
            .headers(req_data.headers);

        if let Some(body_bytes) = req_data.body {
            builder = builder.body(body_bytes);
        }

        // شلیک نهایی
        let response = builder.send().await?;
        
        let final_url = response.url().clone();   // ← این خط رو اضافه کن
        
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.bytes().await?.to_vec();
        
        let res_data = ResponseData {
            url: final_url,           // ← اینم اضافه کن
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
