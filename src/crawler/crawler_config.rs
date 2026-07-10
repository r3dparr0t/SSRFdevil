// crawler_config.rs
//use reqwest::Method;
use url::Url;
use serde::{Serialize, Deserialize};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Target {
    pub url: Url,
    pub kind: TargetKind,
    pub method: String,
    pub source: DiscoverySource,
    pub params: Vec<Param>,
    pub meta: TargetMeta,
}
#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum DiscoverySource {
    Link,
    Form,
    Script,
    Image,
    Iframe,
    Meta,
    Robots,
    Sitemap,
    Embed,
    Object,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)] // <-- Hash رو اضافه کن
pub enum TargetKind {
    Endpoint,
    Resource,
    Document,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TargetMeta {
    pub technologies: Vec<Technology>,
    pub tags: Vec<TargetTag>,
    pub confidence: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetTag {

    // API
    Api,
    GraphQL,
    Rest,
    JsonRpc,
    Soap,

    // Forms
    Form,
    Upload,
    Download,

    // JS
    Fetch,
    Axios,
    XmlHttpRequest,
    WebSocket,
    EventSource,

    // Files
    Js,
    Css,
    Json,
    Xml,
    Pdf,
    Image,
    Video,
    Audio,
    Media,

    // Discovery
    Robots,
    Sitemap,
    Manifest,
    Canonical,
    OpenGraph,
    MetaRefresh,

    // HTML
    Link,
    Script,
    Frame,
    Iframe,

    // Authentication
    Login,
    Logout,

    // SSRF Interesting
    Redirect,
    Callback,
    Webhook,

    // others
    Atom,
    Font,
    Rss, 
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Technology {

    React,
    Vue,
    Angular,
    NextJs,
    Nuxt,

    Django,
    Laravel,
    Rails,
    Spring,

    Express,
    FastApi,

}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Param {
    pub name: String,
    pub value: Option<String>, 
    pub location: ParamLocation,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ParamLocation {
    Query,
    Form,
    Json,
    Header,
    Cookie,
    Path,
}
