// engine/request.rs
use reqwest::{Method, Url};
use reqwest::header::HeaderMap;

pub struct RequestData {
    pub method: Method,
    pub url: Url,
    pub headers: HeaderMap,
    pub body: Option<Vec<u8>>,
}
