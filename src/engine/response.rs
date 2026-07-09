// engine/response.rs
use reqwest::header::HeaderMap;
use url::Url;

pub struct ResponseData {
	pub url: Url,
    pub status: u16,
    pub headers: HeaderMap,
    pub body: Vec<u8>,
}
