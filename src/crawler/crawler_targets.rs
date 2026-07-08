use url::Url;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum TargetKind {
    Get,
    Post,
    Api,
    Redirect,
    File,
    Link,
    Form,
    Js,
    Json,
    Xml,
    Robots,
    Sitemap,
}

#[derive(Debug, Clone)]
pub struct Target {
    pub url: Url,
    pub kind: TargetKind,
    pub params: Vec<String>,
}
