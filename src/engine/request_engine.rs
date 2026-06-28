// engine/request_engine.rs
use std::time::Duration;
use reqwest::Client;
use crate::engine::request::RequestData;
use crate::engine::response::ResponseData;
use crate::engine::{delay_engine, header_engine, ua_engine, cookie_engine, trace_engine};

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
}

pub struct RequestEngine {
    client: Client,
    config: EngineConfig,
}

impl RequestEngine {
    pub fn new(config: EngineConfig) -> Self {
        let mut builder = Client::builder().timeout(config.timeout);

        builder = match config.redirects {
            RedirectPolicy::None => builder.redirect(reqwest::redirect::Policy::none()),
            RedirectPolicy::Limited(n) => builder.redirect(reqwest::redirect::Policy::limited(n)),
            RedirectPolicy::Follow => builder.redirect(reqwest::redirect::Policy::default()),
        };

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

        // تبدیل مدل داده‌ی ما به درخواستِ واقعیِ Reqwest
        let mut builder = self.client.request(req_data.method, req_data.url)
            .headers(req_data.headers);

        if let Some(body_bytes) = req_data.body {
            builder = builder.body(body_bytes);
        }

        // شلیک نهایی
        let response = builder.send().await?;

        // ساخت ResponseData جهت خروجی کپسوله شده
        let status = response.status().as_u16();
        let headers = response.headers().clone();
        let body = response.bytes().await?.to_vec();

        let res_data = ResponseData { status, headers, body };

        // ۴. Trace After
        if self.config.trace {
            trace_engine::after(&res_data);
        }

        Ok(res_data)
    }
}
