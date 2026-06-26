use reqwest::{Client, Method, RequestBuilder};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use ssrfdevil::executor::LuaPayload;

fn build_request_from_payload(client: &Client, payload: &LuaPayload) -> RequestBuilder {
    // ۱. تعیین متد به صورت داینامیک
    let method = match payload.method.to_uppercase().as_str() {
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        _ => Method::GET,
    };

    // ۲. ساخت رکوئست اولیه با URL تولید شده توسط لوا
    let mut req_builder = client.request(method, &payload.url);

    // ۳. تزریق تمام هدرهایی که لوا (و بخش یوزرایجنت دیروز) تولید کردن
    let mut headers = HeaderMap::new();
    for (key, value) in &payload.headers {
        if let (Ok(h_name), Ok(h_val)) = (
            HeaderName::from_bytes(key.as_bytes()),
            HeaderValue::from_str(value)
        ) {
            headers.insert(h_name, h_val);
        }
    }
    req_builder = req_builder.headers(headers);

    // ۴. اضافه کردن بدنه در صورت وجود
    if let Some(ref body_content) = payload.body {
        req_builder = req_builder.body(body_content.clone());
    }

    req_builder
}
